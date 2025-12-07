/*
 * silkhook - hooking example
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include "../include/silkhook.h"

typedef int (*fn_t)(int, int);
static fn_t orig_fn = NULL;

/*  forcing arm mode on arm32 for compat  */
#ifdef __arm__
#define SILKHOOK_FUNC __attribute__((noinline, target("arm")))
#else
#define SILKHOOK_FUNC __attribute__((noinline))
#endif


SILKHOOK_FUNC
int target(int x, int y)
{
    int a = x + 1;
    int b = y + 1;
    return a + b - 2;
}

SILKHOOK_FUNC
int detour(int x, int y)
{
    printf("silkhook:    intercepted(%d, %d)\n", x, y);
    int r = orig_fn(x, y);
    printf("silkhook:    orig returned %d\n", r);
    return r * 2;
}

static int (*volatile targ_ptr)(int, int) = target;

int main(void)
{
    struct silkhook_hook h;
    int r;

    printf("silkhook: loaded !!!\n");

    r = silkhook_init();
    if (r != SILKHOOK_OK)
    {
        printf("silkhook: init failure: %s\n", silkhook_strerror(r));
        return 1;
    }

    printf("silkhook: target @ %p\n", (void *) target);
    printf("silkhook: detour @ %p\n", (void *) detour);
    printf("silkhook: before hook -> %d\n", targ_ptr(3, 4));

    r = silkhook_hook((void *) target, (void *) detour, &h, (void **) &orig_fn);
    if (r != SILKHOOK_OK)
    {
        printf("silkhook: hook failure: %s\n", silkhook_strerror(r));
        return 1;
    }

    printf("silkhook: hook installed !!!\n");
    printf("silkhook:    trampoline @ %p\n", (void *) h.trampoline);

    r = targ_ptr(3, 4);
    printf("silkhook: after hook -> %d\n", r);

    silkhook_unhook(&h);
    printf("silkhook: hook removed !!!\n");
    printf("silkhook: after unhook -> %d\n", targ_ptr(3, 4));

    silkhook_shutdown();
    printf("silkhook: unloaded !!!\n");
    return 0;
}
