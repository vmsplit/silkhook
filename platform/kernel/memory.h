/*
 * silkhook - miniature arm hooking lib
 * memory.h - kernel memory operations
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _SILKHOOK_KERNEL_MEMORY_H_
#define _SILKHOOK_KERNEL_MEMORY_H_

#include <linux/types.h>


int silkhook_mem_init(void);

int __mem_make_rw(void *addr, size_t len);
int __mem_make_rx(void *addr, size_t len);
int __mem_alloc_exec(size_t size, void **out);
int __mem_free(void *ptr, size_t size);
int __mem_write_code(void *dst, const void *src, size_t len);
int __mem_write_text(void *dst, const void *src, size_t len);
void __flush_icache(void *addr, size_t len);


#endif /* _SILKHOOK_KERNEL_MEMORY_H_ */
