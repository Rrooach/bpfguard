# SPDX-License-Identifier: GPL-2.0-only

SHELL := /bin/sh

CURDIR_ABS := $(abspath .)
KERNEL_ROOT := $(abspath ../../..)

OUTPUT ?= $(CURDIR_ABS)/.output
CARGO_TARGET_DIR ?= $(OUTPUT)/cargo-target
CARGO_HOME_DIR ?= $(OUTPUT)/cargo-home
BUILD_TMPDIR ?= $(OUTPUT)/tmp

CARGO ?= cargo
CC ?= cc
CLANG ?= clang-14
LLVM_STRIP ?= llvm-strip-14
BPF_ARCH ?= x86

BPF_SOURCE := bpf/recorder.bpf.c
BPF_HEADER := bpf/recorder.h
BPF_OBJECT := $(OUTPUT)/recorder.bpf.o
BPF_UAPI_HEADERS := \
	$(KERNEL_ROOT)/tools/include/uapi/linux/bpf.h \
	$(KERNEL_ROOT)/tools/include/uapi/linux/types.h

WORKLOAD_SOURCES := $(wildcard workloads/*.c)
WORKLOAD_BINS := $(patsubst workloads/%.c,$(OUTPUT)/workloads/%,$(WORKLOAD_SOURCES))
WORKLOAD_COMMON_HEADERS := workloads/exclusive-credentials.h

CARGO_ENV = CARGO_HOME=$(CARGO_HOME_DIR) CARGO_TARGET_DIR=$(CARGO_TARGET_DIR) \
	TMPDIR=$(BUILD_TMPDIR) CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \
	CARGO_UNSTABLE_SPARSE_REGISTRY=true
BPF_INCLUDES := -I$(KERNEL_ROOT)/tools/include/uapi
BPF_CFLAGS ?= -g -O2 -target bpf -D__TARGET_ARCH_$(BPF_ARCH) -Wall -Wextra -Werror
WORKLOAD_CFLAGS ?= -O2 -g -std=c11 -Wall -Wextra -Werror

STRICT_INIT_SOURCE := vm/strict-init.c
STRICT_INIT_BINARY := $(OUTPUT)/vm/strict-init
STRICT_GUEST_RUNNER := vm/guest-strict-e2e.sh
STRICT_INIT_CFLAGS ?= -Os -std=c11 -Wall -Wextra -Werror -static

VM_KERNEL_OUTPUT ?= $(OUTPUT)/vm-kernel
VM_KERNEL_JOBS ?= $(shell nproc)
VM_SSH_PORT ?= 10022

.DEFAULT_GOAL := all

.PHONY: all release check check-all test fmt-check clippy bpf workloads \
	vm-strict vm-strict-check vm-kernel vm-e2e clean help dirs

all: dirs
	$(CARGO_ENV) $(CARGO) build --workspace --locked

release: dirs
	$(CARGO_ENV) $(CARGO) build --workspace --release --locked

check: fmt-check test

check-all: check clippy bpf workloads vm-strict-check

test: dirs
	$(CARGO_ENV) $(CARGO) test --workspace --locked

fmt-check: dirs
	$(CARGO_ENV) $(CARGO) fmt --all -- --check

clippy: dirs
	$(CARGO_ENV) $(CARGO) clippy --workspace --all-targets --locked -- -D warnings

bpf: $(BPF_OBJECT)

workloads: $(WORKLOAD_BINS)

vm-strict: $(STRICT_INIT_BINARY)

vm-strict-check: $(STRICT_INIT_BINARY)
	$(STRICT_INIT_BINARY) --self-test
	bash -n $(STRICT_GUEST_RUNNER)

vm-kernel:
	VM_KERNEL_JOBS="$(VM_KERNEL_JOBS)" vm/build-e2e-kernel.sh \
		--output-dir "$(VM_KERNEL_OUTPUT)"

vm-e2e: check-all release
	@test -n "$(KERNEL_BZIMAGE)" || { \
		echo 'KERNEL_BZIMAGE=/absolute/path/to/bzImage is required' >&2; \
		exit 2; \
	}
	@test -n "$(VM_ROOTFS)" || { \
		echo 'VM_ROOTFS=/absolute/path/to/raw-image is required' >&2; \
		exit 2; \
	}
	@test -n "$(VM_SSH_KEY)" || { \
		echo 'VM_SSH_KEY=/absolute/path/to/private-key is required' >&2; \
		exit 2; \
	}
	SSH_PORT="$(VM_SSH_PORT)" vm/run-e2e.sh \
		--kernel "$(KERNEL_BZIMAGE)" \
		--rootfs "$(VM_ROOTFS)" \
		--ssh-key "$(VM_SSH_KEY)"

dirs:
	mkdir -p $(OUTPUT) $(CARGO_TARGET_DIR) $(CARGO_HOME_DIR) $(BUILD_TMPDIR) \
		$(OUTPUT)/workloads $(OUTPUT)/vm

$(BPF_OBJECT): $(BPF_SOURCE) $(BPF_HEADER) $(BPF_UAPI_HEADERS) | dirs
	TMPDIR=$(BUILD_TMPDIR) $(CLANG) $(BPF_CFLAGS) $(BPF_INCLUDES) -c $< -o $@

$(OUTPUT)/workloads/%: workloads/%.c $(WORKLOAD_COMMON_HEADERS) | dirs
	TMPDIR=$(BUILD_TMPDIR) $(CC) $(WORKLOAD_CFLAGS) $< -o $@

$(STRICT_INIT_BINARY): $(STRICT_INIT_SOURCE) | dirs
	TMPDIR=$(BUILD_TMPDIR) $(CC) $(STRICT_INIT_CFLAGS) $< -o $@

clean:
	@test "$(abspath $(OUTPUT))" = "$(CURDIR_ABS)/.output" || { \
		echo 'refusing clean: OUTPUT must be the project-local .output directory' >&2; \
		exit 2; \
	}
	$(RM) -r -- "$(CURDIR_ABS)/.output"

help:
	@echo 'BPF State Observer build targets:'
	@echo '  all        build the Rust workspace (default)'
	@echo '  release    build optimized Rust binaries'
	@echo '  check      run rustfmt check and unit tests'
	@echo '  check-all  run all Rust checks and compile BPF/C fixtures'
	@echo '  clippy     run Clippy with warnings denied'
	@echo '  bpf        build the self-contained raw-syscall recorder object'
	@echo '  workloads  build dependency-free fixture workloads'
	@echo '  vm-strict  build the static exclusive-boot PID1 supervisor'
	@echo '  vm-kernel  build the disposable x86 smoke-test kernel'
	@echo '  vm-e2e     run the two-boot authenticated exclusive-VM KVM gate'
	@echo '  clean      remove only this project build output'
