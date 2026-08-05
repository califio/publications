CC ?= gcc
NASM ?= nasm

BUILD_DIR := build
HELPER := $(BUILD_DIR)/root_payload_helper
LAUNCHER := $(BUILD_DIR)/root_payload_launcher.bin

CFLAGS := -m64 -O2 -s -fno-stack-protector -fno-asynchronous-unwind-tables -fno-ident
LDFLAGS := -Wl,-z,norelro -Wl,--build-id=none

.PHONY: all clean

all: $(HELPER) $(LAUNCHER)

$(BUILD_DIR):
	mkdir -p $@

$(HELPER): root_payload_helper.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(LAUNCHER): root_payload_launcher.asm | $(BUILD_DIR)
	$(NASM) -f bin -o $@ $<

clean:
	rm -rf -- $(BUILD_DIR)
