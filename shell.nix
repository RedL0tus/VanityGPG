let
    nixpkgs = import <nixpkgs> {
        config.allowUnfree = false;
        overlays = [ ];
    };
    platform_dependencies = if nixpkgs.stdenv.hostPlatform.system == "x86_64-darwin" then "darwin.apple_sdk.frameworks.Security"
        else "";
in
    with nixpkgs;
    stdenv.mkDerivation rec {
        name = "vanityPGP";
        env = buildEnv { name = name; paths = buildInputs; };
        buildInputs = [
            # List packages that should be on the path
            # You can search for package names using nix-env -qaP | grep <name>
            stdenv clang nettle pkg-config capnproto sqlite rustc cargo llvm
            llvmPackages.libclang platform_dependencies
        ];

        LIBCLANG_PATH="${llvmPackages.libclang}/lib";

        shellHook = ''
          export NIX_SHELL_ENV=${name}
        '';
    }
