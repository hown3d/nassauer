FROM build-image as builder
ARG TARGETARCH

WORKDIR /work
COPY . .
ENV CARGO_HOME=/cargo
RUN --mount=type=cache,target=/cargo  \ 
  --mount=type=cache,target=/work/target \
  make CARGO_FLAGS="--artifact-dir=out -Z unstable-options" build


FROM debian:bookworm 
ARG OPTIMIZATION
ENV RUST_LOG="info"
COPY --from=builder /work/out/nassauer /bin/nassauer
ENTRYPOINT [ "/bin/nassauer" ]

