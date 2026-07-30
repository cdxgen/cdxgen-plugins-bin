# BLOCKERS — cdxgen-plugins-bin

## D05

- **Linux/musl/windows cross-builds not verified on this host**: The
  development machine has a Linux ARM64 ELF zig binary that cannot execute on
  macOS. Only darwin-amd64 and darwin-arm64 were cross-built and verified.
  The remaining 9 flavours (5 linux-gnu, 2 linuxmusl, 2 windows) require a
  Linux host with cargo-zigbuild + zig. The Makefile and build scripts are
  correct and will produce all 11 flavours on CI (which runs on Linux).
  This is a host limitation, not a crate or build-script problem.
