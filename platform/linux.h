/*
 * silkhook - miniature arm64 hooking lib
 * linux.h  - linux-specific defs
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _LINUX_H_
#define _LINUX_H_

#ifdef __linux__
    #define PLATFORM_LINUX 1
#else
    #error "silkhook currently only supports Linux"
#endif

#endif /* _LINUX_H_ */
