ARCH := $(shell uname -m)

run:
	docker run --platform=linux/$(ARCH) --cap-add BPF --cap-add SYS_ADMIN $(FLAGS) --cap-add NET_ADMIN nassauer 

debug: FLAGS = -e RUST_BACKTRACE=1 -e RUST_LOG=debug
debug: run

image: builder-image
	docker build --platform=linux/$(ARCH) -t  nassauer .

builder-image:
	docker build --no-cache --platform=linux/$(ARCH) -t builder-image -f Dockerfile.build .
