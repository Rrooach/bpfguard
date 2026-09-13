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
SYSTEM_EFFECTS_BPF_SOURCE := bpf/system_effects.bpf.c
SYSTEM_EFFECTS_BPF_HEADER := bpf/system_effects.h
SYSTEM_EFFECTS_BPF_OBJECT := $(OUTPUT)/system_effects.bpf.o
BPF_UAPI_HEADERS := \
	$(KERNEL_ROOT)/tools/include/uapi/linux/bpf.h \
	$(KERNEL_ROOT)/tools/include/uapi/linux/types.h
BPF_HELPER_DEFS := $(OUTPUT)/bpf-include/bpf_helper_defs.h

WORKLOAD_SOURCES := $(wildcard workloads/*.c)
WORKLOAD_BINS := $(patsubst workloads/%.c,$(OUTPUT)/workloads/%,$(WORKLOAD_SOURCES))
WORKLOAD_COMMON_HEADERS := workloads/exclusive-credentials.h

CARGO_ENV = CARGO_HOME=$(CARGO_HOME_DIR) CARGO_TARGET_DIR=$(CARGO_TARGET_DIR) \
	TMPDIR=$(BUILD_TMPDIR) CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \
	CARGO_UNSTABLE_SPARSE_REGISTRY=true
BPF_INCLUDES := -I$(KERNEL_ROOT)/tools/include/uapi -I$(KERNEL_ROOT)/tools/lib \
	-I$(OUTPUT)/bpf-include
BPF_CFLAGS ?= -g -O2 -target bpf -D__TARGET_ARCH_$(BPF_ARCH) -Wall -Wextra -Werror
WORKLOAD_CFLAGS ?= -O2 -g -std=c11 -Wall -Wextra -Werror

STRICT_INIT_SOURCE := vm/strict-init.c
STRICT_INIT_BINARY := $(OUTPUT)/vm/strict-init
STRICT_GUEST_RUNNER := vm/guest-strict-e2e.sh
EFFECTS_SUPERVISOR_E2E_DRIVER := vm/effects-supervisor-e2e.sh
STRICT_INIT_CFLAGS ?= -Os -std=c11 -Wall -Wextra -Werror -static

AGENT_LAUNCHER_SOURCE := experiments/codex-deepseek/vm/codex-task-launcher.c
AGENT_LAUNCHER_BINARY := $(OUTPUT)/agent-collection/codex-task-launcher
AGENT_LAUNCHER_CFLAGS ?= -Os -std=c11 -Wall -Wextra -Werror -static
AGENT_VALIDATOR_BINARY := $(CARGO_TARGET_DIR)/release/agent-collection-assert

OVERHEAD_HOST_RUNNER := experiments/overhead/vm/run-overhead.sh
OVERHEAD_GUEST_RUNNER := experiments/overhead/vm/guest-run-overhead.sh
OVERHEAD_ANALYZER := experiments/overhead/analyze.js
OVERHEAD_MEASURE_SMOKE := $(OUTPUT)/tmp/overhead-measure-smoke.json
OVERHEAD_SSH_PORT ?= 10044
OVERHEAD_REPETITIONS ?= 12

VM_KERNEL_OUTPUT ?= $(OUTPUT)/vm-kernel
VM_EFFECTS_KERNEL_OUTPUT ?= $(OUTPUT)/vm-kernel-effects
VM_KERNEL_JOBS ?= $(shell nproc)
VM_EFFECTS_PAHOLE ?= $(OUTPUT)/toolchain/install-static/bin/pahole
VM_SSH_PORT ?= 10022

.DEFAULT_GOAL := all

.PHONY: all release check check-all test fmt-check clippy bpf system-effects-bpf workloads \
	vm-strict vm-strict-check agent-collection-launcher \
	agent-collection-check overhead-check system-effects-overhead-check \
	overhead-e2e vm-kernel vm-effects-kernel vm-e2e \
	clean help dirs

all: dirs
	$(CARGO_ENV) $(CARGO) build --workspace --locked

release: dirs
	$(CARGO_ENV) $(CARGO) build --workspace --release --locked

check: fmt-check test

check-all: check clippy bpf workloads vm-strict-check agent-collection-check \
	overhead-check system-effects-overhead-check

test: dirs
	$(CARGO_ENV) $(CARGO) test --workspace --locked

fmt-check: dirs
	$(CARGO_ENV) $(CARGO) fmt --all -- --check

clippy: dirs
	$(CARGO_ENV) $(CARGO) clippy --workspace --all-targets --locked -- -D warnings

bpf: $(BPF_OBJECT) $(SYSTEM_EFFECTS_BPF_OBJECT)

system-effects-bpf: $(SYSTEM_EFFECTS_BPF_OBJECT)

workloads: $(WORKLOAD_BINS)

vm-strict: $(STRICT_INIT_BINARY)

vm-strict-check: $(STRICT_INIT_BINARY)
	$(STRICT_INIT_BINARY) --self-test
	bash -n $(STRICT_GUEST_RUNNER)
	bash -n $(EFFECTS_SUPERVISOR_E2E_DRIVER)

agent-collection-launcher: $(AGENT_LAUNCHER_BINARY)

agent-collection-check: $(AGENT_LAUNCHER_BINARY)
	$(CARGO_ENV) $(CARGO) build --release --locked --bin agent-collection-assert
	$(AGENT_LAUNCHER_BINARY) --self-test
	$(AGENT_VALIDATOR_BINARY) --self-test
	bash -n experiments/codex-deepseek/vm/fetch-model-catalog.sh
	bash -n experiments/codex-deepseek/vm/guest-run-suite.sh
	bash -n experiments/codex-deepseek/vm/run-collection.sh

overhead-check: workloads
	$(OUTPUT)/workloads/overhead-bench --mode noop --iterations 0 > /dev/null
	! $(OUTPUT)/workloads/overhead-bench --mode getpid --iterations 1 \
		--batch-size 1 --pause-us 1 > /dev/null 2>&1
	$(RM) -- "$(OVERHEAD_MEASURE_SMOKE)"
	$(OUTPUT)/workloads/measure-command "$(OVERHEAD_MEASURE_SMOKE)" -- /bin/true
	grep -q '"exit_code":0' "$(OVERHEAD_MEASURE_SMOKE)"
	$(RM) -- "$(OVERHEAD_MEASURE_SMOKE)"
	bash -n $(OVERHEAD_GUEST_RUNNER)
	bash -n $(OVERHEAD_HOST_RUNNER)
	node --check $(OVERHEAD_ANALYZER)

system-effects-overhead-check: system-effects-bpf
	bash experiments/system-effects-overhead/check-bpf-fast-path.sh $(SYSTEM_EFFECTS_BPF_OBJECT)
	bash experiments/system-effects-overhead/check.sh

overhead-e2e: overhead-check release bpf
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
	bash $(OVERHEAD_HOST_RUNNER) \
		--kernel "$(KERNEL_BZIMAGE)" \
		--rootfs "$(VM_ROOTFS)" \
		--ssh-key "$(VM_SSH_KEY)" \
		--ssh-port "$(OVERHEAD_SSH_PORT)" \
		--repetitions "$(OVERHEAD_REPETITIONS)"

vm-kernel:
	VM_KERNEL_JOBS="$(VM_KERNEL_JOBS)" vm/build-e2e-kernel.sh \
		--output-dir "$(VM_KERNEL_OUTPUT)"

vm-effects-kernel:
	@test -x "$(VM_EFFECTS_PAHOLE)" || { \
		echo 'VM_EFFECTS_PAHOLE must name executable pahole >= 1.22' >&2; \
		exit 2; \
	}
	PAHOLE="$(VM_EFFECTS_PAHOLE)" VM_KERNEL_JOBS="$(VM_KERNEL_JOBS)" \
		vm/build-e2e-kernel.sh --profile effects-object \
		--output-dir "$(VM_EFFECTS_KERNEL_OUTPUT)"

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

$(SYSTEM_EFFECTS_BPF_OBJECT): $(SYSTEM_EFFECTS_BPF_SOURCE) \
		$(SYSTEM_EFFECTS_BPF_HEADER) $(BPF_UAPI_HEADERS) $(BPF_HELPER_DEFS) | dirs
	TMPDIR=$(BUILD_TMPDIR) $(CLANG) $(BPF_CFLAGS) $(BPF_INCLUDES) -c $< -o $@

$(BPF_HELPER_DEFS): $(KERNEL_ROOT)/scripts/bpf_doc.py \
		$(KERNEL_ROOT)/tools/include/uapi/linux/bpf.h | dirs
	mkdir -p $(dir $@)
	$(KERNEL_ROOT)/scripts/bpf_doc.py --header \
		--file $(KERNEL_ROOT)/tools/include/uapi/linux/bpf.h > $@

$(OUTPUT)/workloads/%: workloads/%.c $(WORKLOAD_COMMON_HEADERS) | dirs
	TMPDIR=$(BUILD_TMPDIR) $(CC) $(WORKLOAD_CFLAGS) $< -o $@

$(STRICT_INIT_BINARY): $(STRICT_INIT_SOURCE) | dirs
	TMPDIR=$(BUILD_TMPDIR) $(CC) $(STRICT_INIT_CFLAGS) $< -o $@

$(AGENT_LAUNCHER_BINARY): $(AGENT_LAUNCHER_SOURCE) $(WORKLOAD_COMMON_HEADERS) | dirs
	mkdir -p $(dir $@)
	TMPDIR=$(BUILD_TMPDIR) $(CC) $(AGENT_LAUNCHER_CFLAGS) $< -o $@

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
	@echo '  system-effects-bpf  build the general system-effect recorder object'
	@echo '  workloads  build dependency-free fixture workloads'
	@echo '  vm-strict  build the static exclusive-boot PID1 supervisor'
	@echo '  agent-collection-check  build/check the Codex collection VM helpers'
	@echo '  overhead-check  build/check the overhead benchmark helpers'
	@echo '  system-effects-overhead-check  check the general effect benchmark helpers'
	@echo '  overhead-e2e  run the paired overhead benchmark in disposable KVM'
	@echo '  vm-kernel  build the disposable x86 smoke-test kernel'
	@echo '  vm-effects-kernel  build the BTF+BPF-LSM object-observer test kernel'
	@echo '  vm-e2e     run the two-boot authenticated exclusive-VM KVM gate'
	@echo '  clean      remove only this project build output'
