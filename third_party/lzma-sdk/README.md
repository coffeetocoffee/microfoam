# LZMA SDK (vendored)

Unmodified sources from Igor Pavlov's LZMA SDK, as published in the 7-Zip
source tree. The LZMA SDK is placed in the public domain by its author; the
files carry the SPDX identifier `LZMA-SDK-9.22`.

| File | Upstream path | sha256 |
|---|---|---|
| `LzmaDec.c` | `C/LzmaDec.c` | `4e6ec665a6df01f1722e2b2fc36dc5e3aa7c3890e0f8cb11c6a07c9a01f3309b` |
| `LzmaDec.h` | `C/LzmaDec.h` | `3aaf07b4ae4173a2d103179455dc7089b5ddbc7fc3db3c0e40964a7499c69266` |
| `7zTypes.h` | `C/7zTypes.h` | `a5d03b8cb65cd3a2a56bde46dd68fb356d2ebacd9d70283e7d4d20b4e0a64713` |
| `Precomp.h` | `C/Precomp.h` | `c8903f2e36a771a272d8981e1e9ffed5ba16ca3d2f3dca6d1414d2340a6829d0` |
| `Compiler.h` | `C/Compiler.h` | `d5e42be77d26beaa8c81d3e62ef99fc5685736cfc079779fdb9154d05fa8bc4a` |

Retrieved: 2026-09-30 from `https://raw.githubusercontent.com/ip7z/7zip/master/C/`.

These files are compiled as-is (see `CMakeLists.txt`, target `mcf_lzma_sdk`).
Do not patch them: the whole point of vendoring is that the decoder is the
reviewed upstream implementation, and a local edit would invalidate that.
