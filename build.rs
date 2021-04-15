fn main() {
    #[cfg(target_arch = "aarch64")]
    {
        use cc::Build;
        Build::new().file("src/hex_neon.c").compile("hex");
    }
}
