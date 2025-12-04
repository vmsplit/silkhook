/*
 * silkhook  - miniature arm64 hooking lib
 * memory.h  - memory operations
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _SILKHOOK_MEMORY_H_
#define _SILKHOOK_MEMORY_H_

#ifdef __KERNEL__
    #include <linux/types.h>
#else
    #include <stddef.h>
#endif


/* ─────────────────────────────────────────────────────────────────────────────
 * memory protection
 *
 *   normal:       R - X   <- can't write
 *   during patch: R W X   <- mprotect / fixmap
 *   after patch:  R - X   <- restore
 * ───────────────────────────────────────────────────────────────────────────── */

int __mem_make_rw(void *addr, size_t len);
int __mem_make_rx(void *addr, size_t len);

int __mem_alloc_exec(size_t size, void **out);
int __mem_free(void *ptr, size_t size);

void __flush_icache(void *addr, size_t len);

#ifdef __KERNEL__
int __mem_write_text(void *dst, const void *src, size_t len);
#endif


#endif /* _SILKHOOK_MEMORY_H_ */
