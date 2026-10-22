{
  description = "lexpat — XML 1.0 parsing semantics in Lean 4, with a bounded differential fixture";

  inputs = {
    # nixpkgs tracks `nixos-unstable`; no revision is written here. flake.lock
    # records the revision actually resolved, and `nix flake update nixpkgs`
    # advances it.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    flake-parts.url = "github:hercules-ci/flake-parts";

    treefmt-nix.url = "github:numtide/treefmt-nix";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" ];

      imports = [ inputs.treefmt-nix.flakeModule ];

      perSystem =
        { config, pkgs, ... }:
        let
          # Lean `v4.35.0` is the official binary release, not a source build: the nixpkgs
          # derivation along this line is a release candidate, and overriding it to the final
          # tag would compile Lean from source on first use. This tarball is the exact build
          # `lean-toolchain` names, so an offline run needs no elan download once it is in the
          # store.
          lean4 = pkgs.stdenv.mkDerivation {
            pname = "lean4";
            version = "4.35.0";
            src = pkgs.fetchurl {
              url = "https://releases.lean-lang.org/lean4/v4.35.0/lean-4.35.0-linux.tar.zst";
              hash = "sha256-colZekRUMkbJInuMrlAXZ+CVzhf21Ei5X8So3Jcmj20=";
            };
            nativeBuildInputs = [
              pkgs.autoPatchelfHook
              pkgs.zstd
            ];
            buildInputs = [
              pkgs.stdenv.cc.cc.lib
              pkgs.zlib
            ];
            sourceRoot = "lean-4.35.0-linux";
            unpackPhase = ''
              tar --zstd -xf $src
            '';
            dontStrip = true;
            installPhase = ''
              mkdir -p $out
              cp -a ./. $out/
            '';
          };

          # The dev shell carries the Lean toolchain, a C compiler and `libexpat`'s
          # headers and library for the reference oracle, Python for the
          # differential harness, Valgrind for the release C memory check, and
          # the Clang/LLVM release from the flake-locked nixpkgs for the
          # libFuzzer security targets. A registry lookup would resolve a
          # different nixpkgs revision, so the fuzz toolchain comes from the
          # same `pkgs` set as everything else and `flake.lock` stays put.
          # `expat` is a test oracle only: neither the Lean library, its
          # executable nor the C ABI artifact links system libexpat.
          lexpatShell = pkgs.mkShell {
            name = "lexpat";

            packages = [
              lean4
              pkgs.git
              pkgs.coreutils
              pkgs.zstd
              pkgs.stdenv.cc
              pkgs.llvmPackages_21.clang
              pkgs.llvmPackages_21.llvm
              pkgs.pkg-config
              pkgs.python3
              pkgs.valgrind
              config.treefmt.build.wrapper
            ];

            buildInputs = [
              pkgs.expat
              pkgs.expat.dev
            ];

            shellHook = ''
              # A function beats a PATH entry, so an exported `lean`/`lake`
              # function inherited from the caller's environment would shadow
              # the toolchain binaries.
              unset -f lake lean
              # The LLVM package puts its own `cc` shim on PATH. The checked-in
              # C ABI build scripts select their compiler with `${CC:-cc}`, so
              # keep the stdenv compiler first instead of letting LLVM become
              # the production compiler.
              export PATH="${pkgs.stdenv.cc}/bin:$PATH"
              export CC="${pkgs.stdenv.cc}/bin/cc"
              export CXX="${pkgs.stdenv.cc}/bin/c++"
              # The security fuzz targets must build with the flake-locked
              # LLVM 21.1.8, not the compiler Lean bundles and not a registry
              # lookup. Scripts use this variable explicitly.
              export CLANG="${pkgs.llvmPackages_21.clang}/bin/clang"
              export PKG_CONFIG_PATH="${pkgs.expat.dev}/lib/pkgconfig''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
              # The version banner goes to stderr so that a command run with
              # `nix develop -c` keeps stdout machine-readable.
              printf 'lexpat: %s\n' "$(lean --version)" >&2
            '';
          };
        in
        {
          treefmt = {
            projectRootFile = "flake.nix";

            programs = {
              deadnix.enable = true;
              mdformat.enable = true;
              nixfmt.enable = true;
              shellcheck.enable = true;
              shfmt.enable = true;
              statix.enable = true;
              taplo.enable = true;
            };
          };

          devShells = {
            default = lexpatShell;
            lexpat = lexpatShell;
          };

          packages = {
            inherit lean4;
            default = lexpatShell;
          };
        };
    };
}
