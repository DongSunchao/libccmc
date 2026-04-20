// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2026 Sunchao Dong

/* ebpf/include/zeno_checksum.h */
#ifndef __ZENO_CHECKSUM_H__
#define __ZENO_CHECKSUM_H__

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

/* Incremental TCP checksum update (RFC 1624) */
static __always_inline void
update_csum_16(__sum16 *csum, __be16 old_val, __be16 new_val)
{
    __u32 s = (~(__u32)(*csum) & 0xFFFF)
            + (~(__u32)old_val & 0xFFFF)
            + (__u32)new_val;
    s = (s >> 16) + (s & 0xFFFF);
    s += (s >> 16);
    *csum = (__sum16)~s;
}

static __always_inline void
update_csum_32(__sum16 *csum, __be32 old_val, __be32 new_val)
{
    update_csum_16(csum, (__be16)(old_val & 0xFFFF), (__be16)(new_val & 0xFFFF));
    update_csum_16(csum, (__be16)(old_val >> 16), (__be16)(new_val >> 16));
}

#endif /* __ZENO_CHECKSUM_H__ */
