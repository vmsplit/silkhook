CC      := clang
AR      := ar
CFLAGS  := -std=c99 -Wall -Wextra -Wpedantic -O2 -fPIC
LDFLAGS := -lpthread

SRC_DIR := .
BUILD   := build

SRCS := \
  $(SRC_DIR)/silkhook.c \
  $(SRC_DIR)/internal/assembler.c \
  $(SRC_DIR)/internal/relocator.c \
  $(SRC_DIR)/internal/trampoline.c \
  $(SRC_DIR)/platform/memory.c

OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD)/%.o,$(SRCS))
DEPS := $(OBJS:.o=.d)

LIB_A  := $(BUILD)/libsilkhook.a
LIB_SO := $(BUILD)/libsilkhook.so

.PHONY: all clean example test

all: $(LIB_A) $(LIB_SO)

$(LIB_A): $(OBJS)
	@mkdir -p $(@D)
	$(AR) rcs $@ $^

$(LIB_SO): $(OBJS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -shared -o $@ $^ $(LDFLAGS)

$(BUILD)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

-include $(DEPS)

clean:
	rm -rf $(BUILD)

example: $(LIB_A)
	@mkdir -p $(BUILD)
	$(CC) -std=c99 -Wall -O0 -fno-inline -g \
		-o $(BUILD)/example \
		examples/hook.c \
		-L$(BUILD) -lsilkhook $(LDFLAGS)

test: example
	LD_LIBRARY_PATH=$(BUILD) $(BUILD)/example
