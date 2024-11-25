{pkgs ? import <nixpkgs> {}}:
pkgs.mkShell {
  buildInputs = with pkgs; [
    rustc
    cargo
    gcc

    libpcap
    SDL2
    SDL2_gfx
    SDL2_ttf

    universal-ctags
    rustfmt
    clippy
    cargo-flamegraph

    wireshark-cli
    arp-scan
  ];

  shellHook = ''
    #    podman build -t grcov - <<EOF
    #      FROM docker.io/rust
    #      WORKDIR /srv
    #      RUN rustup component add llvm-tools-preview
    #      RUN cargo install grcov
    #      ENTRYPOINT ["grcov"]
    #    EOF
    #    alias serve='python -m http.server -d ./target/debug/coverage/ &'
    #    alias grcov='podman run -v $PWD:/srv grcov'
    #    alias coverage="grcov . -s src \
    #      --binary-path ./target/debug/ \
    #      -t html --branch --ignore-not-existing \
    #      -o ./target/debug/coverage/"
    alias tests='./run_tests.sh'
  '';

  RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
  LIBPCAP_LIBDIR = "${pkgs.libpcap}/lib";
}
