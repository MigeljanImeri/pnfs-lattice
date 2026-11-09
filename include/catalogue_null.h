/*
 * Copyright (c) 2026 PeakAIO
 * SPDX-License-Identifier: MIT
 *
 * mds_catalogue_null.h -- Null-op catalogue backend.
 *
 * BENCHMARKING AND PROFILING ONLY.  Every mutation is discarded and
 * every point read misses (unless synthesis is enabled).  Never select
 * this backend for a daemon that serves real clients.
 */

#ifndef MDS_CATALOGUE_NULL_H
#define MDS_CATALOGUE_NULL_H

#include <stdint.h>
#include <stdio.h>
#include "mds_catalogue.h"

/* Count every slot invocation (relaxed atomics, cache-line padded).
 * NOTE: shared counters add cross-core traffic; leave this off when
 * measuring raw throughput, turn it on when checking call patterns. */
#define MDS_NULL_CAT_F_COUNT_OPS      (1U << 0)

/* ns_getattr returns a synthesized inode for ANY fileid
 * (root_fileid -> directory, everything else -> regular file). */
#define MDS_NULL_CAT_F_SYNTH_GETATTR  (1U << 1)

/* ns_lookup returns a synthesized regular file for ANY name, with a
 * stable fileid derived from (parent, name).  Note: create paths that
 * pre-check with LOOKUP will then see EXISTS. */
#define MDS_NULL_CAT_F_SYNTH_LOOKUP   (1U << 2)

struct mds_null_cat_opts {
    uint32_t flags;         /**< MDS_NULL_CAT_F_*. */
    uint64_t root_fileid;   /**< 0 => default (1). */
    uint64_t first_fileid;  /**< First id from alloc_fileid; 0 => 1024. */
};

/**
 * Registry entry point (matches the backend table's .open signature).
 * Options come from the environment, since the null backend has no
 * dedicated mds.conf keys:
 *
 *   MDS_NULL_CAT_FLAGS         comma list: count,getattr,lookup,all
 *                              (or a numeric MDS_NULL_CAT_F_* mask)
 *   MDS_NULL_CAT_ROOT_FILEID   default 1
 *   MDS_NULL_CAT_FIRST_FILEID  default 1024
 */
enum mds_status catalogue_null_open(const struct mds_config *cfg,
                                    struct mds_catalogue **out);

/* ---- Profiling introspection (valid only on a null catalogue) ---- */
uint32_t    mds_catalogue_null_op_count(void);
const char *mds_catalogue_null_op_name(uint32_t op);
uint64_t    mds_catalogue_null_op_hits(const struct mds_catalogue *cat,
                                       uint32_t op);
void        mds_catalogue_null_reset(struct mds_catalogue *cat);
/** Print every op with a non-zero hit count. */
void        mds_catalogue_null_dump(const struct mds_catalogue *cat, FILE *fp);
/** True if @cat was produced by catalogue_null_open. */
bool        mds_catalogue_is_null(const struct mds_catalogue *cat);

#endif /* MDS_CATALOGUE_NULL_H */
