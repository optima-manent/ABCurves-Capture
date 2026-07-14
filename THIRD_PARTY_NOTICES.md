# Third-party notices

USBPcap is an external prerequisite and is not bundled. Its kernel driver is
GPL-2.0. The narrow helper's user-space ABI declarations are derived from the
official USBPcapCMD sources under BSD-2-Clause; the relevant source retains the
upstream copyright. The complete terms distributed with binaries are at
`licenses/USBPcap-BSD-2-Clause.txt`.

HIDAPI 0.15.0 is vendored only for its Windows preparsed-data report-descriptor
reconstructor and fixtures. It is BSD-3-Clause licensed; the complete upstream
license is retained in source and distributed with binaries at
`licenses/HIDAPI-BSD-3-Clause.txt`.

zlib 1.3.2 is vendored for streaming standard ZIP Deflate compression and
decompression. It is zlib licensed; the complete upstream license is retained
in source and distributed with binaries at `licenses/ZLIB.txt`.
