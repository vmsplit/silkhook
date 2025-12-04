/*
 * silkhook - miniature arm64 hooking lib
 * ksyms.h  - kernel symbol resolution
 *
 * SPDX-License-Identifier: MIT
 */


#ifndef _SILKHOOK_KSYMS_H_
#define _SILKHOOK_KSYMS_H_

void *silkhook_ksym(const char *name);
void *silkhook_ksym_mod(const char *mod, const char *name);


#endif /* _SILKHOOK_KSYMS_H_ */
