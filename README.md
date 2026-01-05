# nassauer

Nassauer is a ndp-responder using eBPF.
It is heavily inspired by [github.com/yoursunny/ndpresponder](https://github.com/yoursunny/ndpresponder/tree/main) but using eBPF and filtering more in kernel space.

## Build & Run

To build a docker image, use `make image`. You can start the image with `make run`:

## Tests

### Integration tests

Integration tests are implemented using the [ebpf-go](github.com/cilium/ebpf) library using the Go programming language.
This is done because the aya library lacks functionality for the [BPF_PROG_RUN syscall](https://docs.kernel.org/bpf/bpf_prog_run.html).

#### Generating go code for eBPF program and maps

The ebpf-go library contains a powerful program [bpf2go] which compiles the eBPF program with clang and generates go bindings to access maps and programs of the ELF.

Since we do not compile our eBPF code the same way a C eBPF program would be compiled,
the project uses a modified version of this tooling to generate go bindings from the ELF file directly.
It's located at [rustbpf2go](./tests/rustbpf2go) and is invoked using [go generate](./tests/gen.go).
The bindings are generated [./tests/nassauer_bpfel.go](./tests/nassauer_bpfel.go)

There are some missing structs e.g. the structs that are passed into the RingBuffer as aya does not yet support RingBuffers as BTF maps.

## License

With the exception of eBPF code, nassauer is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
