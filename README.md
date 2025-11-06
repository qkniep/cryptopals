# Multi-Language Cryptopals Solutions
On here, I post the solutions to the cryptopals cryptography challenges as I solve them in Rust, C++, Zig, and OCaml.

## Running Solutions

```bash
./scripts/run.sh cpp set1 ch1
```

## Benchmarking Solutions

```bash
./scripts/time.sh set1 ch1
```

## Dependencies
* [OpenSSL](https://www.openssl.org/) for most basic capabilities (Base64, hash functions, etc.)
* [GMP](https://gmplib.org/) for expensive calculations on arbitrary length integers
