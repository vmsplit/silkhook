obj-m := silkhook_test.o

silkhook_test-y := silkhook_kmod.o \
                   internal/trampoline.o \
                   internal/relocator.o \
                   platform/kernel/memory.o \
                   platform/kernel/ksyms.o

ccflags-y := -I$(src)/include -I$(src)/internal -I$(src)/platform
