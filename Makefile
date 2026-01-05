ARCH := $(shell uname -m)
KERNEL := $(shell uname -s)
PREFIX ?= fe80::/64


run:
	docker run -t --platform=linux/$(ARCH) --cap-add BPF --cap-add SYS_ADMIN $(FLAGS) --cap-add NET_ADMIN nassauer --prefix $(PREFIX)

debug: FLAGS = -e RUST_BACKTRACE=1 -e RUST_LOG=debug
debug: run

generate: generate-rust generate-go

generate-go:
	cd tests && go generate ./...

ifeq ($(KERNEL), Linux)
generate-rust: generate-ebpf	
else
generate-rust: generate-ebpf-in-docker
endif

generate-ebpf: 
	RUSTFLAGS="-C debuginfo=2 -C link-arg=--btf -C link-arg=--log-level=debug" \
	RUSTC_LOG=rustc_codegen_ssa::back::link=debug \
  cargo +nightly build \
  -p nassauer-ebpf \
  --target=bpfel-unknown-none -Z build-std=core --release

generate-ebpf-in-docker:
	docker run -t -v $(PWD):/work/nassauer -v $(PWD)/../../aya-rs:/aya-rs -w /work/nassauer  builder-image \
		make generate-ebpf

clippy:
	cargo clippy -p nassauer

ifeq ($(KERNEL), Linux)
test-rust: 
	cargo test --workspace --exclude nassauer-ebpf
else
test-rust: 
	docker run -v $(PWD):/work -w /work builder-image make test-rust
endif

test-ebpf: 
	cd tests && go test -v ./...

test-ebpf-in-docker: 
	docker run -v $(PWD):/work -w /work --privileged golang:1.25 make test-ebpf
	
image: builder-image
	docker build --platform=linux/$(ARCH) --build-context aya=../../aya-rs -t  nassauer .

builder-image:
	docker build --platform=linux/$(ARCH) --target upstream-bpf-linker -t builder-image -f Dockerfile.build .

builder-image-build-linker:
	docker build --platform=linux/$(ARCH) --target build-bpf-linker --build-context bpf-linker=../../aya-rs/bpf-linker -t builder-image -f Dockerfile.build .

obj-dump-section-%:
	docker run -v $(PWD):/work -w /work builder-image llvm-objdump --section=$* -S target/bpfel-unknown-none/release/nassauer-ebpf
