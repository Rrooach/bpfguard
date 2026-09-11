# SPDX-License-Identifier: GPL-2.0-only

KERNEL_SRC ?= ../../../..
CLANG ?= clang-14
ARCH ?= x86
OUTPUT ?= ../.output/recorder.bpf.o

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
	-Wall -Werror \
	-I$(KERNEL_SRC)/tools/include/uapi

.PHONY: all clean dirs

all: $(OUTPUT)

$(OUTPUT): recorder.bpf.c recorder.h | dirs
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

dirs:
	mkdir -p $(dir $(OUTPUT))

clean:
	rm -f -- $(OUTPUT)
