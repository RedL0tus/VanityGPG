VanityGPG (vanity_gpg)
======================

[![license](https://img.shields.io/github/license/RedL0tus/VanityGPG.svg)](LICENSE)
[![crates.io](http://meritbadge.herokuapp.com/vanity_gpg)](https://crates.io/crates/vanity_gpg)

A simple tool for generating and filtering vanity GPG keys, c0nCurr3nt1Y.

Install
-------

With `cargo`:
```bash
cargo install vanity_gpg
```

Usage
-----

```
vanity_gpg 0.1.0
A simple tool for generating and filtering vanity GPG keys, c0nCurr3nt1Y

USAGE:
    vanity_gpg [FLAGS] [OPTIONS] --pattern <pattern>

FLAGS:
    -h, --help       Prints help information
    -v, --verbose    Verbose level
    -V, --version    Prints version information

OPTIONS:
    -j, --jobs <concurrent-jobs>    Concurrent key generation jobs [default: 1]
    -f, --file <params-filename>    File storing GPG batch generation parameters [default: params]
    -p, --pattern <pattern>         Regex pattern for matching fingerprints
```
