CC      := clang
AR      := ar
CFLAGS  := -std=c99 -Wall -Wextra -Wpedantic -O2 -fPIC

SRC_DIR := .
BUILD   := build

SRCS    := $(SRC_DIR)/silkhook.c \
           $(SRC_DIR)/internal/assembler.c \
           $(SRC_DIR)/internal/relocator.c \
           $(SRC_DIR)/internal/trampoline.c \
           $(SRC_DIR)/platform/memory.c

OBJS    := $(SRCS:$(SRC_DIR)/%.c=$(BUILD)/%.o)
DEPS    := $(OBJS:.o=.d)

LIB_A   := $(BUILD)/libsilkhook.a
LIB_SO  := $(BUILD)/libsilkhook.so

.PHONY: all clean example

all: $(LIB_A) $(LIB_SO)

$(LIB_A): $(OBJS)
	@mkdir -p $(@D)
	$(AR) rcs $@ $^

$(LIB_SO): $(OBJS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -shared -o $@ $^

$(BUILD)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

-include $(DEPS)

clean:
	rm -rf $(BUILD)

example: $(LIB_A)
	$(CC) -std=c99 -Wall -O0 -fno-inline -g -o $(BUILD)/example examples/hook.c -Lbuild -lsilkhook
