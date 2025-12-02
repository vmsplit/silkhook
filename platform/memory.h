/*
 * silkhook  - miniature arm64 hooking lib
 * memory.h  - mem operations
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _MEMORY_H_
#define _MEMORY_H_

#include <stddef.h>


/* ─────────────────────────────────────────────────────────────────────────────
 * mem protection
 *
 *   normal:       R - X   <- can't write
 *   during patch: R W X   <- mprotect enables write
 *   after patch:  R - X   <- restore
 * ───────────────────────────────────────────────────────────────────────────── */

int mem_protect(void *addr, size_t len, int prot);
int mem_make_writable(void *addr, size_t len);
int mem_make_exec(void *addr, size_t len);

int mem_alloc_exec(size_t size, void **out);
int mem_free(void *ptr, size_t size);

void flush_icache(void *addr, size_t len);


#endif /* _MEMORY_H_ */
