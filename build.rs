fn main() {
    #[cfg(target_arch = "aarch64")]
    {
        use cc::Build;
        Build::new().file("src/hex_neon.c").compile("hex");
    }
    #[cfg(all(
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
        ),
        feature = "msa"
    ))]
    {
        use cc::Build;
        Build::new()
            .file("src/hex_msa.c")
            .flag("-mmsa")
            .flag("-flax-vector-conversions")
            .compile("hex");
    }
}
