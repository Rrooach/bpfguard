# SPDX-License-Identifier: GPL-2.0-only

KERNEL_SRC ?= ../../../..
CLANG ?= clang-14
ARCH ?= x86
OUTPUT ?= ../.output/recorder.bpf.o
EFFECTS_OUTPUT ?= ../.output/system_effects.bpf.o
LIFECYCLE_OUTPUT ?= ../.output/process_lifecycle.bpf.o
BPF_HELPER_DEFS ?= $(dir $(EFFECTS_OUTPUT))bpf-include/bpf_helper_defs.h

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
	-Wall -Werror \
	-I$(KERNEL_SRC)/tools/include/uapi -I$(KERNEL_SRC)/tools/lib \
	-I$(dir $(BPF_HELPER_DEFS))

.PHONY: all effects lifecycle clean dirs

all: $(OUTPUT)

effects: $(EFFECTS_OUTPUT)

lifecycle: $(LIFECYCLE_OUTPUT)

$(OUTPUT): recorder.bpf.c recorder.h | dirs
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(EFFECTS_OUTPUT): system_effects.bpf.c system_effects.h $(BPF_HELPER_DEFS) | dirs
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(LIFECYCLE_OUTPUT): process_lifecycle.bpf.c process_lifecycle.h $(BPF_HELPER_DEFS) | dirs
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BPF_HELPER_DEFS): $(KERNEL_SRC)/scripts/bpf_doc.py \
		$(KERNEL_SRC)/tools/include/uapi/linux/bpf.h | dirs
	mkdir -p $(dir $@)
	$(KERNEL_SRC)/scripts/bpf_doc.py --header \
		--file $(KERNEL_SRC)/tools/include/uapi/linux/bpf.h > $@

dirs:
	mkdir -p $(dir $(OUTPUT))

clean:
	rm -f -- $(OUTPUT) $(EFFECTS_OUTPUT) $(LIFECYCLE_OUTPUT)
