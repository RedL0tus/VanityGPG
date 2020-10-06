VanityGPG (vanity_gpg)
======================

[![license](https://img.shields.io/github/license/RedL0tus/VanityGPG.svg)](LICENSE)
[![crates.io](http://meritbadge.herokuapp.com/vanity_gpg)](https://crates.io/crates/vanity_gpg)

A simple tool for generating and filtering vanity GPG keys (a.k.a. A OpenPGP key fingerprint collision tool), c0nCurr3nt1Y.

Install
-------

Currently(v0.3), VanityGPG offers two sets of backends. If you have `libclang` available in your system, the default sequoia backend is recommend. 

Install dependencies (assuming you are using Ubuntu, bruh) for the sequoia backend:
```bash
apt install git rustc cargo clang make pkg-config nettle-dev libssl-dev capnproto libsqlite3-dev
```

Install VanityGPG with `cargo`:
```bash
cargo install vanity_gpg
```

If your system does not offer `libclang`, there is also a pure rust `rPGP` backend available:

```bash
cargo install vanity_gpg --no-default-features --features rpgp
```

Performance
-----------

|         System/Backend        |           Sequoia          |            rPGP            |
|-------------------------------|----------------------------|----------------------------|
| Tegra210@2.0GHz (Jetson Nano) |  ~5,000,000 fingerprints/s |  ~5,000,000 fingerprints/s |
| Intel Xeon E3-1231 V3@3.4GHz  | ~10,000,000 fingerprints/s | ~10,000,000 fingerprints/s |
|  Intel Core i7-8569U@2.8GHz   |  ~7,000,000 fingerprints/s |  ~7,000,000 fingerprints/s |

Credits
-------

`Sequoia-OpenPGP` and the `rPGP` team for their awesome works.

@nwalfield for the extremely helpful tips that improves VanityGPG's performance for several orders of magnitude.

Usage
-----

```
vanity_gpg 0.3.0
A simple tool for generating and filtering vanity GPG keys, c0nCurr3nt1Y

USAGE:
    vanity_gpg [FLAGS] [OPTIONS] --pattern <pattern>

FLAGS:
    -d, --dry-run    Dry run (does not save matched keys)
    -h, --help       Prints help information
    -v, --verbose    Verbose level
    -V, --version    Prints version information

OPTIONS:
    -c, --cipher-suite <cipher-suite>
            Cipher suite [default: Ed25519] [possible values: Ed25519, RSA2048, RSA3072, RSA4096,
            NISTP256, NISTP384, NISTP521]

    -j, --jobs <jobs>                    Number of threads [default: 8]
    -p, --pattern <pattern>              Regex pattern for matching fingerprints
    -u, --user-id <user-id>              OpenPGP compatible user ID
```

Notes:
 - There will be an extra thread spawned for displaying summary.
 - It's recommended to use multiple rules with regex for maximum efficiency.