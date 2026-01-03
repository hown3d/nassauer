ARCH := $(shell uname -m)
KERNEL := $(shell uname -s)


run:
	docker run --platform=linux/$(ARCH) --cap-add BPF --cap-add SYS_ADMIN $(FLAGS) --cap-add NET_ADMIN nassauer 

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
	RUSTFLAGS="-C debuginfo=2 -C link-arg=--btf" \
  cargo +nightly build \
  -p nassauer-ebpf \
  --target=bpfel-unknown-none -Z build-std=core --release

generate-ebpf-in-docker:
	docker run -v $(PWD):/work -w /work builder-image \
		make generate-ebpf

test-ebpf: 
	cd tests && go test -v ./...

test-ebpf-in-docker: 
	docker run -v $(PWD):/work -w /work --privileged golang:1.25 make test-ebpf
	
image: builder-image
	docker build --platform=linux/$(ARCH) -t  nassauer .

builder-image:
	docker build --no-cache --platform=linux/$(ARCH) -t builder-image -f Dockerfile.build .
