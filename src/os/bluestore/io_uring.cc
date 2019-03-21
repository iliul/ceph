// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

/*
 * Most of the lines below are taken from fio io_uring engine and test.
 */

#include "ceph_io_uring.h"

#ifdef __x86_64__

#include "io_uring.h"

#ifndef __NR_sys_io_uring_setup
#define __NR_sys_io_uring_setup    425
#endif
#ifndef __NR_sys_io_uring_enter
#define __NR_sys_io_uring_enter    426
#endif
#ifndef __NR_sys_io_uring_register
#define __NR_sys_io_uring_register 427
#endif

#define read_barrier()  __asm__ __volatile__("":::"memory")
#define write_barrier() __asm__ __volatile__("":::"memory")


/* Options */

static bool hipri = 0;          /* use IO polling */
static bool sqpoll_thread = 1;  /* use kernel submission/poller thread */
static int  sqpoll_cpu = -1;    /* pin above thread to this CPU */

static int  iodepth_batch_complete_min;

static int io_uring_register_files(struct ioring_data *d, int *fds, size_t nr)
{
  return syscall(__NR_sys_io_uring_register, d->ring_fd,
		 IORING_REGISTER_FILES, fds, nr);
}

static int io_uring_enter(struct ioring_data *d, unsigned int to_submit,
                          unsigned int min_complete, unsigned int flags)
{
  return syscall(__NR_sys_io_uring_enter, d->ring_fd, to_submit,
		 min_complete, flags, NULL, 0);
}

static int ioring_mmap(struct ioring_data *d, struct io_uring_params *p)
{
  struct io_sq_ring *sring = &d->sq_ring;
  struct io_cq_ring *cring = &d->cq_ring;
  void *ptr;

  d->mmap[0].len = p->sq_off.array + p->sq_entries * sizeof(__u32);
  ptr = mmap(0, d->mmap[0].len, PROT_READ | PROT_WRITE,
	     MAP_SHARED | MAP_POPULATE, d->ring_fd,
	     IORING_OFF_SQ_RING);
  if (ptr == MAP_FAILED)
    return -errno;

  d->mmap[0].ptr = ptr;
  sring->head = (unsigned int *)((char *)ptr + p->sq_off.head);
  sring->tail = (unsigned int *)((char *)ptr + p->sq_off.tail);
  sring->ring_mask = (unsigned int *)((char *)ptr + p->sq_off.ring_mask);
  sring->ring_entries = (unsigned int *)((char *)ptr + p->sq_off.ring_entries);
  sring->flags = (unsigned int *)((char *)ptr + p->sq_off.flags);
  sring->array = (unsigned int *)((char *)ptr + p->sq_off.array);
  d->sq_ring_mask = *sring->ring_mask;

  d->mmap[1].len = p->sq_entries * sizeof(struct io_uring_sqe);
  d->sqes = (struct io_uring_sqe *)mmap(0, d->mmap[1].len, PROT_READ | PROT_WRITE,
					MAP_SHARED | MAP_POPULATE, d->ring_fd,
					IORING_OFF_SQES);
  if (d->sqes == MAP_FAILED) {
    munmap(d->mmap[0].ptr, d->mmap[0].len);
    return -errno;
  }

  d->mmap[1].ptr = d->sqes;

  d->mmap[2].len = p->cq_off.cqes +
    p->cq_entries * sizeof(struct io_uring_cqe);
  ptr = mmap(0, d->mmap[2].len, PROT_READ | PROT_WRITE,
	     MAP_SHARED | MAP_POPULATE, d->ring_fd,
	     IORING_OFF_CQ_RING);
  if (ptr == MAP_FAILED) {
    munmap(d->mmap[0].ptr, d->mmap[0].len);
    munmap(d->mmap[1].ptr, d->mmap[1].len);
    return -errno;
  }

  d->mmap[2].ptr = ptr;
  cring->head = (unsigned int *)((char *)ptr + p->cq_off.head);
  cring->tail = (unsigned int *)((char *)ptr + p->cq_off.tail);
  cring->ring_mask = (unsigned int *)((char *)ptr + p->cq_off.ring_mask);
  cring->ring_entries = (unsigned int *)((char *)ptr + p->cq_off.ring_entries);
  cring->cqes = (struct io_uring_cqe *)((char *)ptr + p->cq_off.cqes);
  d->cq_ring_mask = *cring->ring_mask;

  return 0;
}

static void ioring_unmap(struct ioring_data *d)
{
  unsigned int i;

  for (i = 0; i < sizeof(d->mmap)/sizeof(d->mmap[0]); i++)
    munmap(d->mmap[i].ptr, d->mmap[i].len);
  close(d->ring_fd);
}

static int ioring_cqring_reap(struct ioring_data *d, unsigned int events,
                              unsigned int max, struct aio_t **paio)
{
  struct io_cq_ring *ring = &d->cq_ring;
  struct io_uring_cqe *cqe;
  struct aio_t *io;

  unsigned head, reaped = 0;

  head = *ring->head;
  do {
    read_barrier();
    if (head == *ring->tail)
      break;
    cqe = &ring->cqes[head & d->cq_ring_mask];
    if (cqe->flags & IOCQE_FLAG_CACHEHIT)
      d->cachehit++;
    else
      d->cachemiss++;

    io = (struct aio_t *)(uintptr_t) cqe->user_data;
    io->rval = cqe->res;

    paio[reaped + events] = io;

    reaped++;
    head++;
  } while (reaped + events < max);

  d->queued -= reaped;
  *ring->head = head;
  write_barrier();

  return reaped;
}

static int ioring_getevents(struct ioring_data *d, unsigned int min,
                            unsigned int max, struct aio_t **paio)
{
  unsigned actual_min = iodepth_batch_complete_min == 0 ? 0 : min;
  struct io_cq_ring *ring = &d->cq_ring;
  unsigned events = 0;
  int r;

  if (!d->queued)
    return 0;

  d->cq_ring_off = *ring->head;
  do {
    r = ioring_cqring_reap(d, events, max, paio);
    if (r) {
      events += r;
      continue;
    }

    if (!sqpoll_thread) {
      r = io_uring_enter(d, 0, actual_min,
			 IORING_ENTER_GETEVENTS);
      if (r < 0) {
	if (errno == EAGAIN)
	  continue;
	printf("io_uring_enter: errno %d\n", errno);
	break;
      }
    }
  } while (events < min);

  return r < 0 ? r : events;
}

static int find_fixed_fd(struct ioring_data *d, int real_fd)
{
  auto it = d->fixed_fds_map.find(real_fd);
  if (it == d->fixed_fds_map.end())
    return -1;

  return it->second;
}

static void init_io(struct ioring_data *d, unsigned index, struct aio_t *io)
{
  struct io_uring_sqe *sqe = &d->sqes[index];

  if (io->iocb.aio_lio_opcode == IO_CMD_PWRITEV)
    sqe->opcode = IORING_OP_WRITEV;
  else if (io->iocb.aio_lio_opcode == IO_CMD_PREADV)
    sqe->opcode = IORING_OP_READV;
  else
    ceph_assert(0);

  sqe->flags = IOSQE_FIXED_FILE;
  sqe->fd = find_fixed_fd(d, io->fd);

  ceph_assert(sqe->fd != -1);

  sqe->addr = (unsigned long) &io->iov[0];
  sqe->len = io->iov.size();
  sqe->buf_index = 0;

  sqe->ioprio = 0;
  sqe->off = io->offset;
  sqe->user_data = (unsigned long) io;
}

static inline bool sq_ring_needs_enter(struct io_sq_ring *ring)
{
  return !sqpoll_thread || (*ring->flags & IORING_SQ_NEED_WAKEUP);
}

static int ioring_queue(struct ioring_data *d, void *priv,
			list<aio_t>::iterator beg, list<aio_t>::iterator end)
{
  struct io_sq_ring *ring = &d->sq_ring;
  struct aio_t *io;

  unsigned index, tail, next_tail, max_ios, prepped = 0;
  int ret = 0;

  ceph_assert(beg != end);

  if (d->queued == d->iodepth)
    /* Queue is full, go and reap something first */
    return 0;

  max_ios = d->iodepth - d->queued;
  next_tail = tail = *ring->tail;
  do {
    next_tail++;
    read_barrier();
    if (next_tail == *ring->head)
      break;

    io = &*beg;
    io->priv = priv;

    index = tail & d->sq_ring_mask;
    init_io(d, index, io);
    ring->array[index] = index;
    tail = next_tail;
    prepped++;
    beg++;
  } while (prepped < max_ios && beg != end);

  if (*ring->tail != tail) {
    /* order tail store with writes to sqes above */
    write_barrier();
    *ring->tail = tail;
    write_barrier();
  }

  d->queued += prepped;

  /*
   * Only need to call io_uring_enter if we're not using SQ thread
   * poll, or if IORING_SQ_NEED_WAKEUP is set.
   */
  if (d->queued && sq_ring_needs_enter(ring)) {
    unsigned flags = 0;

    if ((*ring->flags & IORING_SQ_NEED_WAKEUP))
      flags |= IORING_ENTER_SQ_WAKEUP;

    ret = io_uring_enter(d, d->queued, 0, flags);
  }

  return ret ?: prepped;
}

static void build_fixed_fds_map(struct ioring_data *d, std::vector<int> &fds)
{
  int fixed_fd = 0;
  for (int real_fd : fds) {
    d->fixed_fds_map[real_fd] = fixed_fd++;
  }
}

int ioring_queue_t::init(std::vector<int> &fds)
{
  struct io_uring_params p;
  int ret;

  memset(&p, 0, sizeof(p));

  if (hipri)
    p.flags |= IORING_SETUP_IOPOLL;
  if (sqpoll_thread) {
    p.flags |= IORING_SETUP_SQPOLL;
    if (sqpoll_cpu != -1) {
      p.flags |= IORING_SETUP_SQ_AFF;
      p.sq_thread_cpu = sqpoll_cpu;
    }
  }

  ret = syscall(__NR_sys_io_uring_setup, _ioring.iodepth, &p);
  if (ret < 0)
    return ret;

  _ioring.ring_fd = ret;

  ret = io_uring_register_files(&_ioring, &fds[0], fds.size());
  if (ret < 0) {
    close(_ioring.ring_fd);
    return ret;
  }

  build_fixed_fds_map(&_ioring, fds);

  ret = ioring_mmap(&_ioring, &p);
  if (ret < 0)
    close(_ioring.ring_fd);

  return ret;
}

void ioring_queue_t::shutdown()
{
  _ioring.fixed_fds_map.clear();
  ioring_unmap(&_ioring);
}

int ioring_queue_t::submit_batch(aio_iter beg, aio_iter end,
                                 uint16_t aios_size, void *priv,
                                 int *retries)
{
  (void)aios_size;
  (void)retries;

  return ioring_queue(&_ioring, priv, beg, end);
}

int ioring_queue_t::get_next_completed(int timeout_ms, aio_t **paio, int max)
{
  (void)timeout_ms;

  return ioring_getevents(&_ioring, 0, max, paio);
}

bool ioring_queue_t::supported()
{
  struct io_uring_params p;
  int fd;

  memset(&p, 0, sizeof(p));
  fd = syscall(__NR_sys_io_uring_setup, 16, &p);
  if (fd < 0)
    return false;

  close(fd);

  return true;
}

#else // #ifdef __x86_64__

int ioring_queue_t::init(std::vector<int> &fds)
{
  ceph_assert(0);
}

void ioring_queue_t::shutdown()
{
  ceph_assert(0);
}

int ioring_queue_t::submit_batch(aio_iter beg, aio_iter end,
                                 uint16_t aios_size, void *priv,
                                 int *retries)
{
  ceph_assert(0);
}

int ioring_queue_t::get_next_completed(int timeout_ms, aio_t **paio, int max)
{
  ceph_assert(0);
}

bool ioring_queue_t::supported()
{
  return false;
}

#endif // #ifdef __x86_64__
