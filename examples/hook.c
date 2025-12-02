/*
 * silkhook - example
 */

#include <stdio.h>
#include "../include/silkhook.h"


typedef int (*target_fn_t)(int, int);
static target_fn_t original_fn = NULL;


__attribute__((noinline))
int target_function(int x, int y)
{
    int a = x + 1;
    int b = y + 1;
    int c = a + b;
    return c - 2;
}

__attribute__((noinline))
int detour_function(int x, int y)
{
    printf("silkhook:    intercepted target_function(%d, %d)\n", x, y);
    int result = original_fn(x, y);
    printf("silkhook:    original returned %d\n", result);
    return result * 2;
}


static int (*volatile target_ptr)(int, int) = target_function;

int main(void)
{
    struct hook h;
    int status;

    printf("silkhook: loaded !!!\n");

    status = init();
    if (status != OK)
    {
        printf("silkhook: init failed: %s\n", status_str(status));
        return 1;
    }

    printf("silkhook: target_function @ %p\n", (void *)target_function);
    printf("silkhook: detour_function @ %p\n", (void *)detour_function);
    printf("silkhook: before hook, target_function(3, 4) = %d\n", target_ptr(3, 4));

    status = hook(
        (void *)target_function,
        (void *)detour_function,
        &h,
        (void **)&original_fn
    );

    if (status != OK)
    {
        printf("silkhook: hook failure: %s\n", status_str(status));
        return 1;
    }

    printf("silkhook: hook installed !!!\n");
    printf("silkhook:    trampoline @ %p\n", (void *)h. trampoline);
    printf("silkhook:    original_fn @ %p\n", (void *)original_fn);
    printf("silkhook: after hook, target_function(3, 4) = %d\n", target_ptr(3, 4));

    status = unhook(&h);
    if (status != OK)
    {
        printf("silkhook: unhook failure: %s\n", status_str(status));
        return 1;
    }

    printf("silkhook: hook removed !!!\n");
    printf("silkhook: after unhook, target_function(3, 4) = %d\n", target_ptr(3, 4));

    shutdown();
    printf("silkhook: unloaded\n");
    return 0;
}
