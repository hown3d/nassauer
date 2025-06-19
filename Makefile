CARGO_FLAGS := 

run:
	docker run --cap-add BPF --cap-add SYS_ADMIN --cap-add NET_ADMIN nassauer 
image: build-image
	docker build -t nassauer --build-arg OPTIMIZATION=debug .

build-in-docker: build-image build-ebpf-docker build-userspace-docker

build: build-ebpf build-userspace

build-image:
	docker build -t build-image -f Dockerfile.build .
	docker volume create nassauer-cache || true

build-userspace:
	cargo build ${CARGO_FLAGS} --package nassauer  --bins 

build-userspace-docker:
	docker run --rm \
		-v nassauer-cache:/cargo \
		-v .:/code -w /code \
		-e CARGO_HOME="/cargo" \
		build-image \
		make build-userspace

fmt-docker:
	docker run --rm \
		-v nassauer-cache:/cargo \
		-v .:/code -w /code \
		-e CARGO_HOME="/cargo" \
		build-image \
		rustup component add rustfmt && cargo fmt

build-ebpf:
	cd nassauer-ebpf && cargo build  --bin nassauer-ebpf  --release

build-ebpf-docker: build-image
	# need to build with release flag, otherwise llvm complains
	docker run --rm \
		-v nassauer-cache:/cargo \
		-v .:/code -w /code \
		-e CARGO_HOME="/cargo" \
		-w /code \
		build-image \
		make build-ebpf
