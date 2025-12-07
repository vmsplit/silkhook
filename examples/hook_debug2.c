/*
 * silkhook - arm32 debug example v2
 */

#include <stdio.h>
#include <stdint.h>
#include "../include/silkhook.h"

typedef int (*fn_t)(int, int);
static fn_t orig_fn = NULL;

__attribute__((noinline, targ("arm")))
int targ(int x, int y)
{
    int a = x + 1;
    int b = y + 1;
    return a + b - 2;
}

__attribute__((noinline, targ("arm")))
int detour(int x, int y)
{
    printf("silkhook: intercepted(%d, %d)\n", x, y);
    printf("silkhook: orig_fn @ %p\n", (void *)orig_fn);

    int r = orig_fn(x, y);

    printf("silkhook: orig returned %d\n", r);
    return r * 2;
}

static int (*volatile targ_ptr)(int, int) = targ;

static void dump_mem(const char *label, void *addr, size_t len)
{
    uint32_t *p = (uint32_t *)((uintptr_t)addr & ~3);
    printf("%s @ %p (raw %p):\n", label, p, addr);
    for (size_t i = 0; i < len / 4; i++)
    {
        printf("  [%zu] 0x%08x\n", i, p[i]);
    }
}

int main(void)
{
    struct silkhook_hook h;
    int r;

    printf("silkhook: arm32 test loaded !!!\n");
    printf("silkhook: SILKHOOK_HOOK_N_BYTE = %u\n", SILKHOOK_HOOK_N_BYTE);

    r = silkhook_init();
    if (r != SILKHOOK_OK)
    {
        printf("silkhook: init failure: %s\n", silkhook_strerror(r));
        return 1;
    }

    printf("silkhook: targ @ %p (thumb=%d)\n", (void *) targ, ((uintptr_t) targ & 1));
    printf("silkhook: detour @ %p (thumb=%d)\n", (void *) detour, ((uintptr_t) detour & 1));

    dump_mem("targ before hook", (void *) targ, 16);

    printf("silkhook: before hook -> %d\n", targ_ptr(3, 4));

    r = silkhook_hook((void *) targ, (void *) detour, &h, (void **) &orig_fn);
    if (r != SILKHOOK_OK)
    {
        printf("silkhook: hook failure: %s\n", silkhook_strerror(r));
        return 1;
    }

    printf("silkhook: hook installed !!!\n");
    printf("silkhook: trampoline @ %p\n", (void *) h.trampoline);
    printf("silkhook: orig_fn @ %p\n", (void *) orig_fn);

    dump_mem("  targ after hook", (void *) targ, 16);
    dump_mem("  trampoline", (void *) h.trampoline, 32);

    printf("silkhook: calling hooked func...\n");
    r = targ_ptr(3, 4);
    printf("silkhook: after hook -> %d\n", r);

    silkhook_unhook(&h);
    printf("silkhook: hook removed !!!\n");
    printf("silkhook: after unhook -> %d\n", targ_ptr(3, 4));

    silkhook_shutdown();
    printf("silkhook: unloaded !!!\n");
    return 0;
}
