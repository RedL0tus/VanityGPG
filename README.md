VanityGPG (vanity_gpg)
======================

[![license](https://img.shields.io/github/license/RedL0tus/VanityGPG.svg)](LICENSE)
[![crates.io](http://meritbadge.herokuapp.com/vanity_gpg)](https://crates.io/crates/vanity_gpg)

A simple tool for generating and filtering vanity GPG keys, c0nCurr3nt1Y.

Install
-------

Install dependencies (assuming you are using Ubuntu):
```bash
apt install git rustc cargo clang make pkg-config nettle-dev libssl-dev capnproto libsqlite3-dev
```

Install VanityGPG with `cargo`:
```bash
cargo install vanity_gpg
```

Usage
-----

```
vanity_gpg 0.2.0
A simple tool for generating and filtering vanity GPG keys, c0nCurr3nt1Y

USAGE:
    vanity_gpg [FLAGS] [OPTIONS] --pattern <pattern>

FLAGS:
    -d, --dry-run    Dry run (does not save matched keys)
    -h, --help       Prints help information
    -v, --verbose    Verbose level
    -V, --version    Prints version information

OPTIONS:
    -c, --cipher-suite <cipher-suite>    Cipher suite [default: RSA4096]
    -j, --jobs <concurrent-jobs>         Concurrent key generation jobs [default: 1]
    -p, --pattern <pattern>              Regex pattern for matching fingerprints
    -u, --user-id <user-id>              OpenPGP compatible user ID
```
