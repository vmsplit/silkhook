/*
 * silkhook - miniature arm hooking lib
 * svc.h    - EL0 SVC handler hooking
 */

#ifndef _SILKHOOK_SVC_H_
#define _SILKHOOK_SVC_H_

#include <linux/types.h>
#include "shadow.h"

#define SVC_ORIG_INSTR_COUNT 8


struct silkhook_svc_hook {
    void      *invoke_syscall;
    void      *sys_call_table;
    int       target_sysno;
    int       installed;
    uint32_t  orig_instrs[SVC_ORIG_INSTR_COUNT];
    size_t    orig_size;
    struct silkhook_shadow_tbl shadow;
};

int silkhook__svc_init(struct silkhook_svc_hook *h);
int silkhook__svc_install(struct silkhook_svc_hook *h, int sysno, void *detour);
int silkhook__svc_remove(struct silkhook_svc_hook *h);

#endif /* _SILKHOOK_SVC_H_ */
