FROM build-image as builder
ARG TARGETARCH

ENV CARGO_HOME=/cargo

WORKDIR /work
COPY . .


RUN --mount=type=cache,target=/cargo  \ 
  --mount=type=cache,target=/work/target \
  RUSTFLAGS="-C debuginfo=2 -C link-arg=--btf --verbose" \
  cargo build \
  -p nassauer-ebpf \
  --target=bpfel-unknown-none -Z build-std=core --release

RUN --mount=type=cache,target=/cargo  \ 
  --mount=type=cache,target=/work/target \
  cargo build --artifact-dir=out -Z unstable-options --package nassauer --bins --release


FROM debian:bookworm 
ENV RUST_LOG="info"
COPY --from=builder /work/out/nassauer /bin/nassauer
ENTRYPOINT [ "/bin/nassauer" ]

