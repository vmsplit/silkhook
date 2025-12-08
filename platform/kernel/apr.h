/*
 * silkhook - miniature arm hooking lib
 * apr.h    - async page remapping
 *
 * SPDX-License-Identifier: MIT
 *
 * technique:
 *   maintain two phys pages for one virt addr
 *   swap between hooked/clean versions via PTE manip
 *   atomic and without code patching
 */

#ifndef _SILKHOOK_APR_H_
#define _SILKHOOK_APR_H_

#include <linux/types.h>
#include <linux/mm_types.h>


struct silkhook_apr_hook
{
    void        *targ;
    void        *shadow;

    phys_addr_t orig_phys;
    phys_addr_t hook_phys;

    pte_t       *ptep;
    pte_t       orig_pte;

    unsigned long pfn_orig;
    unsigned long pfn_hook;

    int         active;
    int         installed;
};


int silkhook__apr_init(void);
void silkhook__apr_exit(void);

int silkhook__apr_install(struct silkhook_apr_hook *h, void *targ,
                          void *hook_func, size_t func_len);
int silkhook__apr_remove(struct silkhook_apr_hook *h);

void silkhook__apr_enable(struct silkhook_apr_hook *h);
void silkhook__apr_disable(struct silkhook_apr_hook *h);
int silkhook__apr_is_active(struct silkhook_apr_hook *h);

void silkhook__apr_oneshot(struct silkhook_apr_hook *h);


#endif /* _SILKHOOK_APR_H_ */
