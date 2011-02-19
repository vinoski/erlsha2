# SHA-224, SHA-256, SHA-384, SHA-512 implemented in Erlang NIFs.

## Description

The **erlsha2** library application implements the SHA-2 Secure Hash Standard
(SHA-224, SHA-256, SHA-384, SHA-512) using Erlang NIFs. It also
provides pure Erlang implementations, though they are much slower than
the C NIF implementations.

See the following links for details:

* [Secure Hash Standard (PDF)](href="http://csrc.nist.gov/publications/fips/fips180-3/fips180-3_final.pdf")
* [Wikipedia SHA1 article](href="http://en.wikipedia.org/wiki/SHA1")

The code implemented here was written by simply following the
algorithm descriptions provided in the standard. Provided functions
follow the same style as those found in the standard Erlang `crypto`
module: for each hash variant there's a simple function returning a
binary digest and a set of three functions for initializing a digest
context, updating the context with additional data to be hashed, and
finalizing the context to get a binary digest result.

## Building and Installing

The **erlsha2** app is built with
[rebar](https://github.com/basho/rebar), which must be in the command `PATH`.

### Erlang Version

The **erlsha2** app requires Erlang R14B or later.
