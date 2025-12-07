/*
 * silkhook - miniature arm hooking lib
 * ksyms.h  - kallsyms resolution
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _SILKHOOK_KSYMS_H_
#define _SILKHOOK_KSYMS_H_


int silkhook_ksyms_init(void);
void *silkhook_ksym(const char *name);


#endif /* _SILKHOOK_KSYMS_H_ */
