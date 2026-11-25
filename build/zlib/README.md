Debian metadata for our two zlib packages, filled in by build/Dockerfile
(@VERSION@, @ARCH@, @SIZE@, @GLIBC@ are replaced at build time).

- `*.control`  the package "ID card": same name, Source, Provides, Breaks and
  Multi-Arch as Debian's zlib1g / zlib1g-dev, so they replace them 1:1.
  `Source: zlib` stays on purpose: scanners must keep seeing this as zlib.
- `zlib1g.shlibs`  makes packages built against us (nginx) depend on
  zlib1g (>= 1:1.4-0+echo1).
- `zlib1g.triggers`  runs ldconfig after install.
