# nassauer

Nassauer is a ndp-responder using eBPF.
It is heavily inspired by [github.com/yoursunny/ndpresponder](https://github.com/yoursunny/ndpresponder/tree/main) but using eBPF and filtering more in kernel space.

## Build & Run

To build a docker image, use `make image`. You can start the image with `make run`:

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
