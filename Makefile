CC      := clang
AS      := clang
AR      := ar
CFLAGS  := -std=c99 -Wall -Wextra -Wpedantic -O2 -fPIC
ASFLAGS := -c
LDFLAGS := -lpthread

BUILD   := build

ARCH := $(shell uname -m)

ifeq ($(ARCH),aarch64)
ARCH_SRCS := internal/relocator.c internal/arm64.S
endif

ifeq ($(ARCH),armv7l)
ARCH_SRCS := internal/relocator_arm32.c
endif

C_SRCS := silkhook.c \
          internal/trampoline.c \
          $(filter %.c,$(ARCH_SRCS)) \
          platform/user/memory.c

S_SRCS := $(filter %.S,$(ARCH_SRCS))

C_OBJS := $(C_SRCS:%.c=$(BUILD)/%.o)
S_OBJS := $(S_SRCS:%.S=$(BUILD)/%.o)
OBJS   := $(C_OBJS) $(S_OBJS)

.PHONY: all clean example test module module-clean

all: $(BUILD)/libsilkhook.a $(BUILD)/libsilkhook.so

$(BUILD)/libsilkhook.a: $(OBJS)
	@mkdir -p $(@D)
	$(AR) rcs $@ $^

$(BUILD)/libsilkhook.so: $(OBJS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -shared -o $@ $^ $(LDFLAGS)

$(BUILD)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

$(BUILD)/%.o: %.S
	@mkdir -p $(@D)
	$(AS) $(ASFLAGS) -o $@ $<

-include $(C_OBJS:.o=.d)

clean:
	rm -rf $(BUILD)

example: $(BUILD)/libsilkhook.a
	$(CC) -std=c99 -Wall -O0 -fno-inline -g \
		-o $(BUILD)/example examples/hook.c \
		-L$(BUILD) -lsilkhook $(LDFLAGS)

test: example
	LD_LIBRARY_PATH=$(BUILD) $(BUILD)/example


# ─────────────────────────────────────────────────────────────────────────────
# Kernel module
# ─────────────────────────────────────────────────────────────────────────────

KDIR ?= /lib/modules/$(shell uname -r)/build

module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

module-clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
