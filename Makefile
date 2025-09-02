run:
	docker run --cap-add BPF --cap-add SYS_ADMIN $(FLAGS) --cap-add NET_ADMIN nassauer 

debug: FLAGS = -e RUST_BACKTRACE=1 -e RUST_LOG=debug
debug: run

image: builder-image
	docker build -t nassauer .

builder-image:
	docker build -t builder-image -f Dockerfile.build .
