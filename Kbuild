obj-m := silkhook_test.o

silkhook_test-y := \
	silkhook_kmod.o \
	silkhook.o \
	internal/trampoline.o \
	internal/relocator.o \
	platform/kernel/memory.o \
	platform/kernel/ksyms.o \
	platform/kernel/sync.o \
	platform/kernel/pgtable.o \
	platform/kernel/hide.o \
	platform/kernel/shadow.o \
	platform/kernel/svc.o \
	platform/kernel/svc_hook.o

ccflags-y := -I$(src)/include -DSILKHOOK_ARCH_ARM64
