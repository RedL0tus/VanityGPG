let
    nixpkgs = import <nixpkgs> {
        config.allowUnfree = false;
        overlays = [ ];
    };
in
    with nixpkgs;
    stdenv.mkDerivation rec {
        name = "vanityPGP";
        env = buildEnv { name = name; paths = buildInputs; };
        buildInputs = [
            # List packages that should be on the path
            # You can search for package names using nix-env -qaP | grep <name>
            stdenv clang nettle pkg-config capnproto sqlite darwin.apple_sdk.frameworks.Security
        ];

        shellHook = ''
          export NIX_SHELL_ENV=${name}
        '';
    }
