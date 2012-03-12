# SHA-224, SHA-256, SHA-384, SHA-512 implemented in Erlang NIFs.

## Description

The **erlsha2** library application implements the SHA-2 Secure Hash
Standard (SHA-224, SHA-256, SHA-384, SHA-512) using Erlang NIFs. (It
also provides pure Erlang implementations, though they are much slower
than the C NIF implementations.) It also includes HMAC wrappers for
the SHA-2 functions.

See the following links for details:

* [Secure Hash Standard (PDF)](http://csrc.nist.gov/publications/fips/fips180-3/fips180-3_final.pdf)
* [Wikipedia SHA1 article](http://en.wikipedia.org/wiki/SHA1)

The code implemented here was written by simply following the
algorithm descriptions provided in the standard. Provided functions
follow the same style as those found in the standard Erlang `crypto`
module: for each hash variant there's a simple function returning a
binary digest and a set of three functions for initializing a digest
context, updating the context with additional data to be hashed, and
finalizing the context to get a binary digest result.

This implementation replaces and obsoletes the
[original pure Erlang implementation](http://steve.vinoski.net/code/sha2.erl).

## Building and Installing

The **erlsha2** app is built with
[rebar](https://github.com/basho/rebar), which must be in the command
`PATH`.

I don't use Windows at all so I doubt it builds there. I don't know of
any reason it shouldn't work there, though; you'll just have to build
it manually. If nothing else, you could comment out the `on_load`
directive in the Erlang file to prevent it from loading the NIF
implementation, thereby gaining access to the pure Erlang
implementation instead, but note that it's much slower than the C
code.

If you run into any build trouble, first make sure the version of
`rebar` you're using is reasonably up to date.

### Erlang Version

The **erlsha2** app requires Erlang R14B or later.
