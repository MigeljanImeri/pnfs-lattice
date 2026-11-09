/*
 * Copyright (c) 2026 PeakAIO
 * SPDX-License-Identifier: MIT
 *
 * catalogue_null.c -- Null-op catalogue backend (benchmarking only).
 *
 * Slot contract notes (see catalogue_internal.h):
 *  C1/C2/C3  No locks, no retries, no transactions; callbacks are never
 *            invoked because no entries exist.
 *  C5        Every populated slot genuinely implements its op for a
 *            store that retains nothing.  Slots with no honest null
 *            meaning (bootstrap, backend_handle, image feed, prealloc
 *            pool, cluster ops) are left NULL.  caps == 0.
 *  C6        txn is ignored.
 *  C7        close frees backend_private only, never cat.
 */

#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "catalogue_internal.h"
#include "catalogue_null.h"

#if defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif

/* -----------------------------------------------------------------------
 * Op table (X-macro) -- one entry per counted slot
 * ----------------------------------------------------------------------- */

#define NC_OPS(X)                                                        \
    X(probe)                                                             \
    /* authority */                                                      \
    X(ns_create) X(ns_create_wide) X(ns_create_with_layout)              \
    X(ns_remove) X(ns_remove_known) X(ns_remove_known_gc)                \
    X(ns_parent_touch)                                                   \
    X(remove_pending_enqueue) X(remove_pending_enqueue_unlink)           \
    X(remove_pending_peek_batch) X(remove_pending_claim)                 \
    X(remove_pending_complete) X(remove_pending_bump_retry)              \
    X(remove_pending_count) X(remove_pending_scan_all)                   \
    X(ns_rename) X(ns_rename_flags) X(ns_link) X(ns_lookup)              \
    X(ns_getattr) X(ns_setattr) X(ns_readdir) X(dirent_name_for_child)   \
    X(ns_readdir_plus) X(ns_readdir_plus_from) X(ns_nlink_adjust)        \
    X(alloc_fileid) X(inode_put) X(inode_del)                            \
    X(dirent_put) X(dirent_insert) X(dirent_del)                         \
    X(inline_get) X(inline_put) X(inline_del)                            \
    X(xattr_get) X(xattr_put) X(xattr_del) X(xattr_list) X(xattr_exists) \
    X(stripe_map_get) X(stripe_map_put) X(stripe_map_del)                \
    X(stripe_map_scan)                                                   \
    X(ds_get) X(ds_put) X(ds_del) X(ds_list)                             \
    X(ds_provision_get) X(ds_provision_put) X(ds_provision_del)          \
    X(quota_rule_get) X(quota_rule_put)                                  \
    X(quota_usage_get) X(quota_usage_put)                                \
    X(gc_enqueue) X(gc_peek) X(gc_dequeue) X(gc_count) X(gc_peek_batch)  \
    X(shard_fileid_get) X(shard_fileid_put) X(shard_fileid_del)          \
    X(ext_dirent_get) X(ext_dirent_put) X(ext_dirent_del)                \
    X(link_anchor_put) X(link_anchor_del) X(backend_client_stats)        \
    /* coordination */                                                   \
    X(journal_put) X(journal_get) X(journal_del) X(journal_scan)         \
    X(layout_grant) X(layout_grant_union) X(layoutget_fused)             \
    X(layout_return) X(layout_get_by_stateid) X(layout_scan_for_file)    \
    X(layout_del_all_for_client) X(ds_layout_idx_scan)                   \
    X(layout_iter_file)                                                  \
    X(recovery_put) X(recovery_del) X(recovery_get) X(recovery_list)     \
    X(open_put) X(open_get) X(open_del)                                  \
    X(open_scan_file) X(open_scan_client)                                \
    X(lock_put) X(lock_del) X(lock_test) X(lock_scan_file)               \
    X(lock_scan_owner) X(lock_reap_client)                               \
    X(deleg_put) X(deleg_get) X(deleg_del)                               \
    X(deleg_scan_file) X(deleg_scan_client)                              \
    X(client_put) X(client_get) X(client_del)                            \
    X(session_put) X(session_get) X(session_del) X(session_scan_client)  \
    X(slot_put) X(slot_get)

enum nc_op {
#define X(n) NC_OP_##n,
    NC_OPS(X)
#undef X
    NC_OP__COUNT
};

static const char *const nc_op_names[NC_OP__COUNT] = {
#define X(n) [NC_OP_##n] = #n,
    NC_OPS(X)
#undef X
};

/* -----------------------------------------------------------------------
 * Private state
 * ----------------------------------------------------------------------- */

struct nc_counter {
    _Atomic uint64_t n;
} __attribute__((aligned(64)));   /* avoid false sharing between ops */

struct null_cat {
    uint32_t          flags;
    uint64_t          root_fileid;
    _Atomic uint64_t  next_fileid;
    _Atomic uint64_t  next_remove_seq;
    struct nc_counter hits[NC_OP__COUNT];
};

static inline struct null_cat *nc_of(const struct mds_catalogue *cat)
{
    return (struct null_cat *)cat->backend_private;
}

static inline void nc_hit(struct mds_catalogue *cat, enum nc_op op)
{
    struct null_cat *nc = nc_of(cat);
    if (__builtin_expect(nc->flags & MDS_NULL_CAT_F_COUNT_OPS, 0))
        atomic_fetch_add_explicit(&nc->hits[op].n, 1, memory_order_relaxed);
}

/* Convenience bodies. */
#define NC_OK(op)        do { nc_hit(cat, NC_OP_##op); return MDS_OK; } while (0)
#define NC_MISS(op)      do { nc_hit(cat, NC_OP_##op); return MDS_ERR_NOTFOUND; } while (0)
#define NC_EMPTY_SCAN(op) NC_OK(op)   /* zero entries delivered */

/* -----------------------------------------------------------------------
 * Inode synthesis
 *
 * ADAPT: the field names of struct mds_inode and the mds_file_type
 * enumerators below are assumptions; align them with mds_catalogue.h.
 * Everything not set here stays zero.
 * ----------------------------------------------------------------------- */

static void nc_synth_inode(uint64_t fileid, enum mds_file_type type,
                           uint32_t mode, uint64_t uid, uint64_t gid,
                           struct mds_inode *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    out->fileid = fileid;
    out->type   = type;
    out->mode   = mode;
    out->uid    = uid;
    out->gid    = gid;
    out->nlink  = (type == MDS_FTYPE_DIR) ? 2 : 1;
}

/* Stable synthetic fileid for (parent, name): FNV-1a, high bit set so it
 * can never collide with the allocator range or the root. */
static uint64_t nc_name_fileid(uint64_t parent, const char *name)
{
    uint64_t h = 0xcbf29ce484222325ULL ^ parent;
    for (const unsigned char *p = (const unsigned char *)name; p && *p; p++) {
        h ^= *p;
        h *= 0x100000001b3ULL;
    }
    return h | (1ULL << 63);
}

static uint64_t nc_alloc(struct null_cat *nc)
{
    return atomic_fetch_add_explicit(&nc->next_fileid, 1,
                                     memory_order_relaxed);
}

/* =======================================================================
 * Lifecycle
 * ======================================================================= */

static void nc_close(struct mds_catalogue *cat)
{
    /* C7: release backend-owned state only; the dispatcher frees cat. */
    free(cat->backend_private);
    cat->backend_private = NULL;
}

static enum mds_status nc_probe(struct mds_catalogue *cat) { NC_OK(probe); }

static const struct mds_catalogue_ops null_lifecycle_ops = {
    .close            = nc_close,
    .probe            = nc_probe,
    .bootstrap        = NULL,  /* nothing to bootstrap -> daemon skips loop */
    .backend_handle   = NULL,  /* no native client handle */
    .image_feed_start = NULL,  /* both or neither: neither */
    .image_feed_stop  = NULL,
};

/* =======================================================================
 * Authority ops
 * ======================================================================= */

/* ---- Namespace ---- */

static enum mds_status nc_ns_create(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t parent, const char *name,
    enum mds_file_type type, uint32_t mode, uint64_t uid, uint64_t gid,
    struct ds_prealloc_ctx *prealloc, struct mds_inode *out)
{
    nc_hit(cat, NC_OP_ns_create);
    /* prealloc is deliberately not popped: no stripe map is "persisted". */
    nc_synth_inode(nc_alloc(nc_of(cat)), type, mode, uid, gid, out);
    return MDS_OK;
}

static enum mds_status nc_ns_create_wide(struct mds_catalogue *cat,
    uint64_t parent, const char *name, const struct mds_inode *child,
    uint32_t stripe_count, uint32_t stripe_unit, uint32_t mirror_count,
    const struct mds_ds_map_entry *entries, bool *safe_to_discard)
{
    nc_hit(cat, NC_OP_ns_create_wide);
    if (safe_to_discard)
        *safe_to_discard = false;   /* committed: DS objects are "referenced" */
    return MDS_OK;
}

static enum mds_status nc_ns_create_with_layout(struct mds_catalogue *cat,
    uint64_t parent, const char *name, enum mds_file_type type,
    uint32_t mode, uint64_t uid, uint64_t gid,
    struct ds_prealloc_ctx *prealloc, struct mds_inode *out,
    uint64_t layout_clientid, uint32_t layout_iomode,
    uint64_t layout_offset, uint64_t layout_length,
    const struct nfs4_stateid *layout_stateid, uint32_t layout_mds_id,
    bool *layout_ok, struct mds_ds_map_entry *layout_entry_out,
    uint32_t *layout_pop_stripe_unit_out)
{
    nc_hit(cat, NC_OP_ns_create_with_layout);
    nc_synth_inode(nc_alloc(nc_of(cat)), type, mode, uid, gid, out);
    if (layout_ok)
        *layout_ok = (layout_clientid != 0);
    if (layout_entry_out)
        memset(layout_entry_out, 0, sizeof(*layout_entry_out));
    if (layout_pop_stripe_unit_out)
        *layout_pop_stripe_unit_out = 0;   /* 0 unit = no prealloc pop */
    return MDS_OK;
}

static enum mds_status nc_ns_remove(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t parent, const char *name)
{ NC_OK(ns_remove); }

static enum mds_status nc_ns_remove_known(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t parent, const char *name,
    const struct mds_inode *child, uint32_t stripe_count)
{ NC_OK(ns_remove_known); }

static enum mds_status nc_ns_remove_known_gc(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t parent, const char *name,
    const struct mds_inode *child, uint32_t stripe_count,
    const struct mds_ds_map_entry *gc_entries, uint32_t gc_entry_count,
    uint32_t gc_sweep_hint, bool *gc_folded)
{
    nc_hit(cat, NC_OP_ns_remove_known_gc);
    if (gc_folded)
        *gc_folded = true;   /* final unlink; GC rows "committed" with it */
    return MDS_OK;
}

static enum mds_status nc_ns_parent_touch(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t fileid, uint64_t change_delta,
    struct timespec stamp)
{ NC_OK(ns_parent_touch); }

/* ---- Async-REMOVE manifest ---- */

static enum mds_status nc_rp_enqueue_common(struct mds_catalogue *cat,
    enum nc_op op, uint64_t *seq_out)
{
    nc_hit(cat, op);
    uint64_t seq = atomic_fetch_add_explicit(&nc_of(cat)->next_remove_seq, 1,
                                             memory_order_relaxed);
    if (seq_out)
        *seq_out = seq;
    return MDS_OK;
}

static enum mds_status nc_remove_pending_enqueue(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t dir_fileid, const char *name,
    uint64_t child_fileid, uint64_t child_generation, uint64_t *seq_out)
{ return nc_rp_enqueue_common(cat, NC_OP_remove_pending_enqueue, seq_out); }

static enum mds_status nc_remove_pending_enqueue_unlink(
    struct mds_catalogue *cat, struct mds_cat_txn *txn, uint64_t dir_fileid,
    const char *name, uint64_t child_fileid, uint64_t child_generation,
    uint64_t *seq_out)
{ return nc_rp_enqueue_common(cat, NC_OP_remove_pending_enqueue_unlink,
                              seq_out); }

static enum mds_status nc_remove_pending_peek_batch(struct mds_catalogue *cat,
    uint64_t now_ns, struct mds_remove_pending_entry *entries,
    uint32_t cap, uint32_t *n_out)
{
    nc_hit(cat, NC_OP_remove_pending_peek_batch);
    if (n_out)
        *n_out = 0;
    return MDS_OK;
}

static enum mds_status nc_remove_pending_claim(struct mds_catalogue *cat,
    uint64_t remove_seq, uint32_t mds_id, uint64_t boot_epoch,
    uint64_t now_ns, uint64_t claim_ttl_ns)
{ NC_MISS(remove_pending_claim); }   /* no row can exist to claim */

static enum mds_status nc_remove_pending_complete(struct mds_catalogue *cat,
    uint64_t remove_seq)
{ NC_OK(remove_pending_complete); }

static enum mds_status nc_remove_pending_bump_retry(struct mds_catalogue *cat,
    uint64_t remove_seq)
{ NC_OK(remove_pending_bump_retry); }

static enum mds_status nc_remove_pending_count(struct mds_catalogue *cat,
    uint32_t *count)
{
    nc_hit(cat, NC_OP_remove_pending_count);
    if (count)
        *count = 0;
    return MDS_OK;
}

static enum mds_status nc_remove_pending_scan_all(struct mds_catalogue *cat,
    mds_cat_remove_pending_scan_cb cb, void *ctx)
{ NC_EMPTY_SCAN(remove_pending_scan_all); }

/* ---- Rename / link / lookup / attrs ---- */

static enum mds_status nc_ns_rename(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t src_parent, const char *src_name,
    uint64_t dst_parent, const char *dst_name)
{ NC_OK(ns_rename); }

static enum mds_status nc_ns_rename_flags(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t src_parent, const char *src_name,
    uint64_t dst_parent, const char *dst_name, uint32_t ns_flags)
{ NC_OK(ns_rename_flags); }

static enum mds_status nc_ns_link(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t parent, const char *name,
    uint64_t target)
{ NC_OK(ns_link); }

static enum mds_status nc_ns_lookup(struct mds_catalogue *cat,
    uint64_t parent, const char *name, struct mds_inode *child)
{
    struct null_cat *nc = nc_of(cat);
    nc_hit(cat, NC_OP_ns_lookup);
    if (!(nc->flags & MDS_NULL_CAT_F_SYNTH_LOOKUP))
        return MDS_ERR_NOTFOUND;
    nc_synth_inode(nc_name_fileid(parent, name), MDS_FTYPE_REG, 0644, 0, 0, child);
    return MDS_OK;
}

static enum mds_status nc_ns_getattr(struct mds_catalogue *cat,
    uint64_t fileid, struct mds_inode *inode)
{
    struct null_cat *nc = nc_of(cat);
    nc_hit(cat, NC_OP_ns_getattr);
    if (!(nc->flags & MDS_NULL_CAT_F_SYNTH_GETATTR))
        return MDS_ERR_NOTFOUND;
    if (fileid == nc->root_fileid)
        nc_synth_inode(fileid, MDS_FTYPE_DIR, 0755, 0, 0, inode);
    else
        nc_synth_inode(fileid, MDS_FTYPE_REG, 0644, 0, 0, inode);
    return MDS_OK;
}

static enum mds_status nc_ns_setattr(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t fileid,
    const struct mds_inode *attrs, uint32_t mask)
{ NC_OK(ns_setattr); }

/* ---- Readdir (always an empty directory) ---- */

static enum mds_status nc_ns_readdir(struct mds_catalogue *cat,
    uint64_t parent, const char *start_after, uint32_t max_entries,
    struct mds_cat_txn *txn, mds_readdir_cb cb, void *ctx)
{ NC_EMPTY_SCAN(ns_readdir); }

static enum mds_status nc_dirent_name_for_child(struct mds_catalogue *cat,
    uint64_t parent, uint64_t child_fileid, char *name_out,
    size_t name_out_len)
{
    nc_hit(cat, NC_OP_dirent_name_for_child);
    if (name_out && name_out_len)
        name_out[0] = '\0';
    return MDS_ERR_NOTFOUND;
}

static enum mds_status nc_ns_readdir_plus(struct mds_catalogue *cat,
    uint64_t parent, const char *start_after, uint32_t max_entries,
    struct mds_cat_txn *txn, mds_readdir_plus_cb cb, void *ctx)
{ NC_EMPTY_SCAN(ns_readdir_plus); }

static enum mds_status nc_ns_readdir_plus_from(struct mds_catalogue *cat,
    uint64_t parent, uint64_t start_after_cookie, uint32_t max_entries,
    struct mds_cat_txn *txn, mds_readdir_plus_cb cb, void *ctx)
{ NC_EMPTY_SCAN(ns_readdir_plus_from); }

static enum mds_status nc_ns_nlink_adjust(struct mds_catalogue *cat,
    uint64_t fileid, int32_t delta)
{ NC_OK(ns_nlink_adjust); }

static enum mds_status nc_alloc_fileid(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t *fileid)
{
    nc_hit(cat, NC_OP_alloc_fileid);
    if (!fileid)
        return MDS_ERR_INVAL;
    *fileid = nc_alloc(nc_of(cat));
    return MDS_OK;
}

/* ---- Low-level inode / dirent ---- */

static enum mds_status nc_inode_put(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, const struct mds_inode *inode)
{ NC_OK(inode_put); }

static enum mds_status nc_inode_del(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t fileid)
{ NC_OK(inode_del); }

static enum mds_status nc_dirent_put(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t parent, const char *name,
    uint64_t child_fileid, uint8_t child_type)
{ NC_OK(dirent_put); }

static enum mds_status nc_dirent_insert(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t parent, const char *name,
    uint64_t child_fileid, uint8_t child_type)
{ NC_OK(dirent_insert); }   /* nothing can collide in an empty store */

static enum mds_status nc_dirent_del(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t parent, const char *name)
{ NC_OK(dirent_del); }

/* ---- Inline data ---- */

static enum mds_status nc_inline_get(struct mds_catalogue *cat,
    uint64_t fileid, void *buf, uint32_t buflen, uint32_t *outlen)
{
    nc_hit(cat, NC_OP_inline_get);
    if (outlen)
        *outlen = 0;
    return MDS_ERR_NOTFOUND;
}

static enum mds_status nc_inline_put(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t fileid, const void *buf, uint32_t len)
{ NC_OK(inline_put); }

static enum mds_status nc_inline_del(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t fileid)
{ NC_OK(inline_del); }

/* ---- Xattrs ---- */

static enum mds_status nc_xattr_get(struct mds_catalogue *cat,
    uint64_t fileid, const char *name, void **val, uint32_t *vallen)
{
    nc_hit(cat, NC_OP_xattr_get);
    if (val)
        *val = NULL;
    if (vallen)
        *vallen = 0;
    return MDS_ERR_NOTFOUND;
}

static enum mds_status nc_xattr_put(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t fileid, const char *name,
    const void *val, uint32_t vallen)
{ NC_OK(xattr_put); }

static enum mds_status nc_xattr_del(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t fileid, const char *name)
{ NC_OK(xattr_del); }

static enum mds_status nc_xattr_list(struct mds_catalogue *cat,
    uint64_t fileid, mds_xattr_list_cb cb, void *ctx)
{ NC_EMPTY_SCAN(xattr_list); }

static enum mds_status nc_xattr_exists(struct mds_catalogue *cat,
    uint64_t fileid, const char *name)
{ NC_MISS(xattr_exists); }

/* ---- Stripe maps ---- */

static enum mds_status nc_stripe_map_get(struct mds_catalogue *cat,
    uint64_t fileid, uint32_t *sc, uint32_t *su, uint32_t *mc,
    struct mds_ds_map_entry **entries)
{
    nc_hit(cat, NC_OP_stripe_map_get);
    if (sc) *sc = 0;
    if (su) *su = 0;
    if (mc) *mc = 0;
    if (entries) *entries = NULL;     /* caller-frees contract: nothing */
    return MDS_ERR_NOTFOUND;
}

static enum mds_status nc_stripe_map_put(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t fileid, uint32_t sc, uint32_t su,
    uint32_t mc, const struct mds_ds_map_entry *entries)
{ NC_OK(stripe_map_put); }

static enum mds_status nc_stripe_map_del(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t fileid)
{ NC_OK(stripe_map_del); }

static enum mds_status nc_stripe_map_scan(struct mds_catalogue *cat,
    mds_cat_stripe_map_scan_cb cb, void *ctx)
{ NC_EMPTY_SCAN(stripe_map_scan); }

/* ---- DS registry / provisioning ---- */

static enum mds_status nc_ds_get(struct mds_catalogue *cat,
    uint32_t ds_id, struct mds_ds_info *info)
{ NC_MISS(ds_get); }

static enum mds_status nc_ds_put(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, const struct mds_ds_info *info)
{ NC_OK(ds_put); }

static enum mds_status nc_ds_del(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint32_t ds_id)
{ NC_OK(ds_del); }

static enum mds_status nc_ds_list(struct mds_catalogue *cat,
    struct mds_ds_info **list, uint32_t *count)
{
    nc_hit(cat, NC_OP_ds_list);
    if (list)  *list = NULL;
    if (count) *count = 0;
    return MDS_OK;
}

static enum mds_status nc_ds_provision_get(struct mds_catalogue *cat,
    uint32_t ds_id, uint8_t *secret, uint32_t secret_len, uint64_t *epoch)
{
    nc_hit(cat, NC_OP_ds_provision_get);
    if (epoch)
        *epoch = 0;
    return MDS_ERR_NOTFOUND;
}

static enum mds_status nc_ds_provision_put(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint32_t ds_id, const uint8_t *secret,
    uint32_t secret_len, uint64_t epoch)
{ NC_OK(ds_provision_put); }

static enum mds_status nc_ds_provision_del(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint32_t ds_id)
{ NC_OK(ds_provision_del); }

/* ---- Quota ---- */

static enum mds_status nc_quota_rule_get(struct mds_catalogue *cat,
    uint8_t scope_type, uint64_t scope_id, struct mds_quota_rule *rule)
{ NC_MISS(quota_rule_get); }

static enum mds_status nc_quota_rule_put(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint8_t scope_type, uint64_t scope_id,
    const struct mds_quota_rule *rule)
{ NC_OK(quota_rule_put); }

static enum mds_status nc_quota_usage_get(struct mds_catalogue *cat,
    uint8_t usage_type, uint64_t scope_id, struct mds_quota_usage *usage)
{ NC_MISS(quota_usage_get); }

static enum mds_status nc_quota_usage_put(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint8_t usage_type, uint64_t scope_id,
    const struct mds_quota_usage *usage)
{ NC_OK(quota_usage_put); }

/* ---- GC queue (always empty) ---- */

static enum mds_status nc_gc_enqueue(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t fileid, uint32_t ds_id,
    const uint8_t *nfs_fh, uint32_t fh_len, uint32_t sweep_hint)
{ NC_OK(gc_enqueue); }

static enum mds_status nc_gc_peek(struct mds_catalogue *cat,
    struct mds_gc_entry *entry)
{ NC_MISS(gc_peek); }

static enum mds_status nc_gc_dequeue(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t gc_seq)
{ NC_OK(gc_dequeue); }

static enum mds_status nc_gc_count(struct mds_catalogue *cat, uint32_t *count)
{
    nc_hit(cat, NC_OP_gc_count);
    if (count)
        *count = 0;
    return MDS_OK;
}

static enum mds_status nc_gc_peek_batch(struct mds_catalogue *cat,
    struct mds_gc_entry *entries, uint32_t cap, uint32_t *n_out)
{
    nc_hit(cat, NC_OP_gc_peek_batch);
    if (n_out)
        *n_out = 0;   /* MDS_OK + 0 = empty queue, drainer backs off */
    return MDS_OK;
}

/* ---- Shard routing / ext_dirents / link anchors ---- */

static enum mds_status nc_shard_fileid_get(struct mds_catalogue *cat,
    uint64_t fileid, uint32_t *shard_id)
{ NC_MISS(shard_fileid_get); }

static enum mds_status nc_shard_fileid_put(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t fileid, uint32_t shard_id)
{ NC_OK(shard_fileid_put); }

static enum mds_status nc_shard_fileid_del(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t fileid)
{ NC_OK(shard_fileid_del); }

static enum mds_status nc_ext_dirent_get(struct mds_catalogue *cat,
    uint64_t parent, const char *name, uint32_t *owner_mds_id,
    uint64_t *target_fileid, uint8_t *target_type, uint64_t *anchor_id)
{ NC_MISS(ext_dirent_get); }

static enum mds_status nc_ext_dirent_put(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t parent, const char *name,
    uint32_t owner_mds_id, uint64_t target_fileid, uint8_t target_type,
    uint64_t anchor_id)
{ NC_OK(ext_dirent_put); }

static enum mds_status nc_ext_dirent_del(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t parent, const char *name)
{ NC_OK(ext_dirent_del); }

static enum mds_status nc_link_anchor_put(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t anchor_id, uint32_t remote_mds_id,
    uint64_t parent_fileid, const char *name)
{ NC_OK(link_anchor_put); }

static enum mds_status nc_link_anchor_del(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t anchor_id)
{ NC_OK(link_anchor_del); }

/* Truthful: the null store performs zero round trips / txns / bytes. */
static enum mds_status nc_backend_client_stats(struct mds_catalogue *cat,
    struct mds_cat_backend_client_stats *out)
{
    nc_hit(cat, NC_OP_backend_client_stats);
    if (!out)
        return MDS_ERR_INVAL;
    memset(out, 0, sizeof(*out));
    return MDS_OK;
}

static const struct mds_authority_ops null_auth_ops = {
    .ns_create                     = nc_ns_create,
    .ns_create_wide                = nc_ns_create_wide,
    .ns_create_with_layout         = nc_ns_create_with_layout,
    .ns_remove                     = nc_ns_remove,
    .ns_remove_known               = nc_ns_remove_known,
    .ns_remove_known_gc            = nc_ns_remove_known_gc,
    .ns_parent_touch               = nc_ns_parent_touch,
    .remove_pending_enqueue        = nc_remove_pending_enqueue,
    .remove_pending_enqueue_unlink = nc_remove_pending_enqueue_unlink,
    .remove_pending_peek_batch     = nc_remove_pending_peek_batch,
    .remove_pending_claim          = nc_remove_pending_claim,
    .remove_pending_complete       = nc_remove_pending_complete,
    .remove_pending_bump_retry     = nc_remove_pending_bump_retry,
    .remove_pending_count          = nc_remove_pending_count,
    .remove_pending_scan_all       = nc_remove_pending_scan_all,
    .ns_rename                     = nc_ns_rename,
    .ns_rename_flags               = nc_ns_rename_flags,
    .ns_link                       = nc_ns_link,
    .ns_lookup                     = nc_ns_lookup,
    .ns_getattr                    = nc_ns_getattr,
    .ns_setattr                    = nc_ns_setattr,
    .ns_readdir                    = nc_ns_readdir,
    .dirent_name_for_child         = nc_dirent_name_for_child,
    .ns_readdir_plus               = nc_ns_readdir_plus,
    .ns_readdir_plus_from          = nc_ns_readdir_plus_from,
    .ns_nlink_adjust               = nc_ns_nlink_adjust,
    .alloc_fileid                  = nc_alloc_fileid,
    .inode_put                     = nc_inode_put,
    .inode_del                     = nc_inode_del,
    .dirent_put                    = nc_dirent_put,
    .dirent_insert                 = nc_dirent_insert,
    .dirent_del                    = nc_dirent_del,
    .inline_get                    = nc_inline_get,
    .inline_put                    = nc_inline_put,
    .inline_del                    = nc_inline_del,
    .xattr_get                     = nc_xattr_get,
    .xattr_put                     = nc_xattr_put,
    .xattr_del                     = nc_xattr_del,
    .xattr_list                    = nc_xattr_list,
    .xattr_exists                  = nc_xattr_exists,
    .stripe_map_get                = nc_stripe_map_get,
    .stripe_map_put                = nc_stripe_map_put,
    .stripe_map_del                = nc_stripe_map_del,
    .stripe_map_scan               = nc_stripe_map_scan,
    .ds_get                        = nc_ds_get,
    .ds_put                        = nc_ds_put,
    .ds_del                        = nc_ds_del,
    .ds_list                       = nc_ds_list,
    .ds_provision_get              = nc_ds_provision_get,
    .ds_provision_put              = nc_ds_provision_put,
    .ds_provision_del              = nc_ds_provision_del,
    .quota_rule_get                = nc_quota_rule_get,
    .quota_rule_put                = nc_quota_rule_put,
    .quota_usage_get               = nc_quota_usage_get,
    .quota_usage_put               = nc_quota_usage_put,
    .gc_enqueue                    = nc_gc_enqueue,
    .gc_peek                       = nc_gc_peek,
    .gc_dequeue                    = nc_gc_dequeue,
    .gc_count                      = nc_gc_count,
    .gc_peek_batch                 = nc_gc_peek_batch,
    /* Prealloc pool left NULL: the engine runs in-memory only. */
    .prealloc_pool_insert          = NULL,
    .prealloc_pool_delete          = NULL,
    .prealloc_pool_scan            = NULL,
    .shard_fileid_get              = nc_shard_fileid_get,
    .shard_fileid_put              = nc_shard_fileid_put,
    .shard_fileid_del              = nc_shard_fileid_del,
    .ext_dirent_get                = nc_ext_dirent_get,
    .ext_dirent_put                = nc_ext_dirent_put,
    .ext_dirent_del                = nc_ext_dirent_del,
    .link_anchor_put               = nc_link_anchor_put,
    .link_anchor_del               = nc_link_anchor_del,
    .backend_client_stats          = nc_backend_client_stats,
};

/* =======================================================================
 * Coordination ops
 * ======================================================================= */

/* ---- 2PC journal ---- */

static enum mds_status nc_journal_put(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, const struct mds_coord_journal_record *record)
{ NC_OK(journal_put); }

static enum mds_status nc_journal_get(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t txn_id, uint8_t role,
    struct mds_coord_journal_record *record)
{ NC_MISS(journal_get); }

static enum mds_status nc_journal_del(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t txn_id, uint8_t role)
{ NC_OK(journal_del); }

static enum mds_status nc_journal_scan(struct mds_catalogue *cat,
    mds_coord_journal_scan_cb cb, void *ctx)
{ NC_EMPTY_SCAN(journal_scan); }

/* ---- Layout state ---- */

static enum mds_status nc_layout_grant(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t clientid, uint64_t fileid,
    uint32_t iomode, uint64_t offset, uint64_t length,
    const struct nfs4_stateid *stateid, const uint32_t *ds_ids,
    uint32_t ds_count)
{ NC_OK(layout_grant); }

static enum mds_status nc_layout_grant_union(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t clientid, uint64_t fileid,
    uint32_t iomode, uint64_t offset, uint64_t length,
    const struct nfs4_stateid *stateid, const uint32_t *ds_ids,
    uint32_t ds_count)
{ NC_OK(layout_grant_union); }

static enum mds_status nc_layoutget_fused(struct mds_catalogue *cat,
    uint64_t fileid, uint32_t *stripe_count, uint32_t *stripe_unit,
    uint32_t *mirror_count, struct mds_ds_map_entry **entries,
    const struct nfs4_stateid *stateid, uint64_t clientid,
    uint32_t iomode, uint64_t offset, uint64_t length, uint32_t mds_id)
{
    nc_hit(cat, NC_OP_layoutget_fused);
    /* Same contract as stripe_map_get: no map => NOTFOUND, nothing granted. */
    if (stripe_count) *stripe_count = 0;
    if (stripe_unit)  *stripe_unit  = 0;
    if (mirror_count) *mirror_count = 0;
    if (entries)      *entries      = NULL;
    return MDS_ERR_NOTFOUND;
}

static enum mds_status nc_layout_return(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, const uint8_t stateid_other[12],
    uint64_t clientid, uint64_t fileid, const uint32_t *ds_ids,
    uint32_t ds_count)
{ NC_OK(layout_return); }

static enum mds_status nc_layout_get_by_stateid(struct mds_catalogue *cat,
    const uint8_t stateid_other[12], uint64_t *clientid, uint64_t *fileid,
    uint32_t *iomode, uint64_t *offset, uint64_t *length, uint32_t *seqid)
{ NC_MISS(layout_get_by_stateid); }

static enum mds_status nc_layout_scan_for_file(struct mds_catalogue *cat,
    uint64_t fileid, bool *has_layout)
{
    nc_hit(cat, NC_OP_layout_scan_for_file);
    if (has_layout)
        *has_layout = false;
    return MDS_OK;
}

static enum mds_status nc_layout_del_all_for_client(struct mds_catalogue *cat,
    uint64_t clientid)
{ NC_OK(layout_del_all_for_client); }

static enum mds_status nc_ds_layout_idx_scan(struct mds_catalogue *cat,
    uint32_t ds_id, mds_coord_ds_layout_cb cb, void *ctx)
{ NC_EMPTY_SCAN(ds_layout_idx_scan); }

static enum mds_status nc_layout_iter_file(struct mds_catalogue *cat,
    uint64_t fileid, mds_coord_layout_file_iter_cb cb, void *ctx)
{ NC_EMPTY_SCAN(layout_iter_file); }

/* ---- Client recovery ---- */

static enum mds_status nc_recovery_put(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t clientid, const uint8_t *co_ownerid,
    uint32_t co_ownerid_len, const uint8_t verifier[8])
{ NC_OK(recovery_put); }

static enum mds_status nc_recovery_del(struct mds_catalogue *cat,
    struct mds_cat_txn *txn, uint64_t clientid)
{ NC_OK(recovery_del); }

static enum mds_status nc_recovery_get(struct mds_catalogue *cat,
    uint64_t clientid, uint8_t *co_ownerid, uint32_t *co_ownerid_len,
    uint8_t verifier[8])
{
    nc_hit(cat, NC_OP_recovery_get);
    if (co_ownerid_len)
        *co_ownerid_len = 0;
    return MDS_ERR_NOTFOUND;
}

static enum mds_status nc_recovery_list(struct mds_catalogue *cat,
    uint32_t owner_mds_id, mds_recovery_list_cb cb, void *ctx)
{ NC_EMPTY_SCAN(recovery_list); }

/* ---- Open state ---- */

static enum mds_status nc_open_put(struct mds_catalogue *cat,
    const struct mds_coord_open_row *row)
{ NC_OK(open_put); }

static enum mds_status nc_open_get(struct mds_catalogue *cat,
    const uint8_t stateid_other[12], struct mds_coord_open_row *row)
{ NC_MISS(open_get); }

static enum mds_status nc_open_del(struct mds_catalogue *cat,
    const uint8_t stateid_other[12])
{ NC_OK(open_del); }

static enum mds_status nc_open_scan_file(struct mds_catalogue *cat,
    uint64_t fileid, mds_coord_open_scan_cb cb, void *ctx)
{ NC_EMPTY_SCAN(open_scan_file); }

static enum mds_status nc_open_scan_client(struct mds_catalogue *cat,
    uint64_t clientid, mds_coord_open_scan_cb cb, void *ctx)
{ NC_EMPTY_SCAN(open_scan_client); }

/* ---- Byte-range locks ---- */

static enum mds_status nc_lock_put(struct mds_catalogue *cat,
    const struct mds_coord_lock_row *row)
{ NC_OK(lock_put); }

static enum mds_status nc_lock_del(struct mds_catalogue *cat,
    uint64_t fileid, uint64_t lock_id)
{ NC_OK(lock_del); }

/* ADAPT: assumes MDS_OK == "no conflict" (conflict is never possible). */
static enum mds_status nc_lock_test(struct mds_catalogue *cat,
    uint64_t fileid, uint32_t lock_type, uint64_t offset, uint64_t length,
    uint64_t clientid, const uint8_t *owner, uint32_t owner_len,
    struct mds_coord_lock_row *conflict)
{ NC_OK(lock_test); }

static enum mds_status nc_lock_scan_file(struct mds_catalogue *cat,
    uint64_t fileid, mds_coord_lock_scan_cb cb, void *ctx)
{ NC_EMPTY_SCAN(lock_scan_file); }

static enum mds_status nc_lock_scan_owner(struct mds_catalogue *cat,
    uint64_t clientid, const uint8_t *owner, uint32_t owner_len,
    mds_coord_lock_scan_cb cb, void *ctx)
{ NC_EMPTY_SCAN(lock_scan_owner); }

static enum mds_status nc_lock_reap_client(struct mds_catalogue *cat,
    uint64_t clientid)
{ NC_OK(lock_reap_client); }

/* ---- Delegations ---- */

static enum mds_status nc_deleg_put(struct mds_catalogue *cat,
    const struct mds_coord_deleg_row *row)
{ NC_OK(deleg_put); }

static enum mds_status nc_deleg_get(struct mds_catalogue *cat,
    const uint8_t stateid_other[12], struct mds_coord_deleg_row *row)
{ NC_MISS(deleg_get); }

static enum mds_status nc_deleg_del(struct mds_catalogue *cat,
    const uint8_t stateid_other[12])
{ NC_OK(deleg_del); }

static enum mds_status nc_deleg_scan_file(struct mds_catalogue *cat,
    uint64_t fileid, mds_coord_deleg_scan_cb cb, void *ctx)
{ NC_EMPTY_SCAN(deleg_scan_file); }

static enum mds_status nc_deleg_scan_client(struct mds_catalogue *cat,
    uint64_t clientid, mds_coord_deleg_scan_cb cb, void *ctx)
{ NC_EMPTY_SCAN(deleg_scan_client); }

/* ---- Client identity / sessions / DRC ---- */

static enum mds_status nc_client_put(struct mds_catalogue *cat,
    const struct mds_coord_client_row *row)
{ NC_OK(client_put); }

static enum mds_status nc_client_get(struct mds_catalogue *cat,
    uint64_t clientid, struct mds_coord_client_row *row)
{ NC_MISS(client_get); }

static enum mds_status nc_client_del(struct mds_catalogue *cat,
    uint64_t clientid)
{ NC_OK(client_del); }

static enum mds_status nc_session_put(struct mds_catalogue *cat,
    const struct mds_coord_session_row *row)
{ NC_OK(session_put); }

static enum mds_status nc_session_get(struct mds_catalogue *cat,
    const uint8_t session_id[16], struct mds_coord_session_row *row)
{ NC_MISS(session_get); }

static enum mds_status nc_session_del(struct mds_catalogue *cat,
    const uint8_t session_id[16])
{ NC_OK(session_del); }

static enum mds_status nc_session_scan_client(struct mds_catalogue *cat,
    uint64_t clientid, mds_coord_session_scan_cb cb, void *ctx)
{ NC_EMPTY_SCAN(session_scan_client); }

static enum mds_status nc_slot_put(struct mds_catalogue *cat,
    const uint8_t session_id[16], uint32_t slot_id, uint32_t seq_id,
    const void *cached_reply, uint32_t reply_len)
{ NC_OK(slot_put); }

static enum mds_status nc_slot_get(struct mds_catalogue *cat,
    const uint8_t session_id[16], uint32_t slot_id,
    struct mds_coord_drc_slot_row *row)
{ NC_MISS(slot_get); }

static const struct mds_coordination_ops null_coord_ops = {
    .journal_put               = nc_journal_put,
    .journal_get               = nc_journal_get,
    .journal_del               = nc_journal_del,
    .journal_scan              = nc_journal_scan,
    .layout_grant              = nc_layout_grant,
    .layout_grant_union        = nc_layout_grant_union,
    .layoutget_fused           = nc_layoutget_fused,
    .layout_return             = nc_layout_return,
    .layout_get_by_stateid     = nc_layout_get_by_stateid,
    .layout_scan_for_file      = nc_layout_scan_for_file,
    .layout_del_all_for_client = nc_layout_del_all_for_client,
    .ds_layout_idx_scan        = nc_ds_layout_idx_scan,
    .layout_iter_file          = nc_layout_iter_file,
    .recovery_put              = nc_recovery_put,
    .recovery_del              = nc_recovery_del,
    .recovery_get              = nc_recovery_get,
    .recovery_list             = nc_recovery_list,
    .open_put                  = nc_open_put,
    .open_get                  = nc_open_get,
    .open_del                  = nc_open_del,
    .open_scan_file            = nc_open_scan_file,
    .open_scan_client          = nc_open_scan_client,
    .lock_put                  = nc_lock_put,
    .lock_del                  = nc_lock_del,
    .lock_test                 = nc_lock_test,
    .lock_scan_file            = nc_lock_scan_file,
    .lock_scan_owner           = nc_lock_scan_owner,
    .lock_reap_client          = nc_lock_reap_client,
    .deleg_put                 = nc_deleg_put,
    .deleg_get                 = nc_deleg_get,
    .deleg_del                 = nc_deleg_del,
    .deleg_scan_file           = nc_deleg_scan_file,
    .deleg_scan_client         = nc_deleg_scan_client,
    .client_put                = nc_client_put,
    .client_get                = nc_client_get,
    .client_del                = nc_client_del,
    .session_put               = nc_session_put,
    .session_get               = nc_session_get,
    .session_del               = nc_session_del,
    .session_scan_client       = nc_session_scan_client,
    .slot_put                  = nc_slot_put,
    .slot_get                  = nc_slot_get,
};

/* =======================================================================
 * Registry adapter: config-signature entry point
 * ======================================================================= */

static bool nc_tok_eq(const char *tok, size_t len, const char *word)
{
    return strlen(word) == len && strncmp(tok, word, len) == 0;
}

static uint32_t nc_parse_flags(const char *s)
{
    if (!s || !*s)
        return 0;

    /* Numeric mask form: "0x3", "5", ... */
    char *end;
    unsigned long v = strtoul(s, &end, 0);
    if (end != s && *end == '\0')
        return (uint32_t)v;

    /* Comma-list form: "count,getattr" */
    uint32_t flags = 0;
    for (const char *p = s; *p; ) {
        size_t len = strcspn(p, ",");
        if (len == 0) {
            /* empty token, skip */
        } else if (nc_tok_eq(p, len, "count") ||
                   nc_tok_eq(p, len, "count_ops")) {
            flags |= MDS_NULL_CAT_F_COUNT_OPS;
        } else if (nc_tok_eq(p, len, "getattr") ||
                   nc_tok_eq(p, len, "synth_getattr")) {
            flags |= MDS_NULL_CAT_F_SYNTH_GETATTR;
        } else if (nc_tok_eq(p, len, "lookup") ||
                   nc_tok_eq(p, len, "synth_lookup")) {
            flags |= MDS_NULL_CAT_F_SYNTH_LOOKUP;
        } else if (nc_tok_eq(p, len, "all")) {
            flags |= MDS_NULL_CAT_F_COUNT_OPS |
                     MDS_NULL_CAT_F_SYNTH_GETATTR |
                     MDS_NULL_CAT_F_SYNTH_LOOKUP;
        } else {
            fprintf(stderr,
                    "null catalogue: ignoring unknown flag '%.*s'\n",
                    (int)len, p);
        }
        p += len;
        if (*p == ',')
            p++;
    }
    return flags;
}

static uint64_t nc_env_u64(const char *name)
{
    const char *s = getenv(name);
    if (!s || !*s)
        return 0;                       /* 0 => constructor default */
    char *end;
    unsigned long long v = strtoull(s, &end, 0);
    if (end == s || *end != '\0') {
        fprintf(stderr, "null catalogue: invalid %s='%s', using default\n",
                name, s);
        return 0;
    }
    return (uint64_t)v;
}

/* =======================================================================
 * Constructor
 * ======================================================================= */

enum mds_status catalogue_null_open(const struct mds_config *cfg,
                                        struct mds_catalogue **out)
{
    if (!out)
        return MDS_ERR_INVAL;
    *out = NULL;

    struct mds_null_cat_opts opts = {
        .flags        = nc_parse_flags(getenv("MDS_NULL_CAT_FLAGS")),
        .root_fileid  = nc_env_u64("MDS_NULL_CAT_ROOT_FILEID"),
        .first_fileid = nc_env_u64("MDS_NULL_CAT_FIRST_FILEID"),
    };

    /* ADAPT: allocate cat with the allocator mds_catalogue_close() frees with. */
    struct mds_catalogue *cat = calloc(1, sizeof(*cat));
    struct null_cat *nc = aligned_alloc(64, sizeof(*nc));
    if (!cat || !nc) {
        free(cat);
        free(nc);
        return MDS_ERR_NOMEM;   /* ADAPT: match your enum's spelling */
    }
    memset(nc, 0, sizeof(*nc));

    nc->flags       = opts.flags;
    nc->root_fileid = opts.root_fileid;
    atomic_init(&nc->next_fileid, opts.first_fileid);
    atomic_init(&nc->next_remove_seq, 1);
    for (unsigned i = 0; i < NC_OP__COUNT; i++)
        atomic_init(&nc->hits[i].n, 0);

    cat->backend         = MDS_BACKEND_NULL;  /* new enum value */
    cat->caps            = 0;      /* C5: not shared, not multi-process */
    cat->auth_ops        = &null_auth_ops;
    cat->coord_ops       = &null_coord_ops;
    cat->ops             = &null_lifecycle_ops;
    cat->cluster_ops     = NULL;   /* no cluster services */
    cat->backend_private = nc;
    /* stats / delta_sink / image / cq stay zero/NULL from calloc. */

    fprintf(stderr,
            "WARNING: null catalogue active -- all metadata is discarded. "
            "Benchmarking/profiling use only.\n");

    *out = cat;
    return MDS_OK;
}

/* =======================================================================
 * Profiling introspection
 * ======================================================================= */

bool mds_catalogue_is_null(const struct mds_catalogue *cat)
{
    return cat && cat->ops == &null_lifecycle_ops && cat->backend_private;
}

uint32_t mds_catalogue_null_op_count(void) { return NC_OP__COUNT; }

const char *mds_catalogue_null_op_name(uint32_t op)
{
    return op < NC_OP__COUNT ? nc_op_names[op] : NULL;
}

uint64_t mds_catalogue_null_op_hits(const struct mds_catalogue *cat,
                                    uint32_t op)
{
    if (!mds_catalogue_is_null(cat) || op >= NC_OP__COUNT)
        return 0;
    return atomic_load_explicit(&nc_of(cat)->hits[op].n,
                                memory_order_relaxed);
}

void mds_catalogue_null_reset(struct mds_catalogue *cat)
{
    if (!mds_catalogue_is_null(cat))
        return;
    for (unsigned i = 0; i < NC_OP__COUNT; i++)
        atomic_store_explicit(&nc_of(cat)->hits[i].n, 0,
                              memory_order_relaxed);
}

void mds_catalogue_null_dump(const struct mds_catalogue *cat, FILE *fp)
{
    if (!mds_catalogue_is_null(cat) || !fp)
        return;
    fprintf(fp, "%-32s %16s\n", "op", "calls");
    for (unsigned i = 0; i < NC_OP__COUNT; i++) {
        uint64_t n = mds_catalogue_null_op_hits(cat, i);
        if (n)
            fprintf(fp, "%-32s %16llu\n", nc_op_names[i],
                    (unsigned long long)n);
    }
}
