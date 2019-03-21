// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#pragma once

#include "acconfig.h"

#include "include/types.h"
#include "ceph_aio.h"

struct io_sq_ring {
  unsigned *head;
  unsigned *tail;
  unsigned *ring_mask;
  unsigned *ring_entries;
  unsigned *flags;
  unsigned *array;
};

struct io_cq_ring {
  unsigned *head;
  unsigned *tail;
  unsigned *ring_mask;
  unsigned *ring_entries;
  struct io_uring_cqe *cqes;
};

struct ioring_mmap {
  void *ptr;
  size_t len;
};

struct ioring_data {
  int ring_fd;

  struct io_sq_ring sq_ring;
  struct io_uring_sqe *sqes;
  unsigned sq_ring_mask;

  struct io_cq_ring cq_ring;
  unsigned cq_ring_mask;

  unsigned queued;
  int cq_ring_off;
  unsigned iodepth;

  uint64_t cachehit;
  uint64_t cachemiss;

  struct ioring_mmap mmap[3];

  std::map<int, int> fixed_fds_map;
};

struct ioring_queue_t : public io_queue_t {
  struct ioring_data _ioring;

  typedef list<aio_t>::iterator aio_iter;

  // Returns true if arch is x86-64 and kernel supports io_uring
  static bool supported();

  explicit ioring_queue_t(unsigned iodepth) :
    _ioring() {
    _ioring.iodepth = iodepth;
  }

  int init(std::vector<int> &fds) override;
  void shutdown() override;

  int submit_batch(aio_iter begin, aio_iter end, uint16_t aios_size,
                   void *priv, int *retries) override;
  int get_next_completed(int timeout_ms, aio_t **paio, int max) override;
};
