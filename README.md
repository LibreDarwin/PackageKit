# PackageKit

Clean-room, BSD-3 reimplementation of Apple's internal PackageKit
repository for the LibreDarwin release-control toolchain.

Apple's PackageKit repo is closed-source; it is *not* part of the
Apple Open Source releases and must not be confused with the
Linux PackageKit abstraction layer.  It ships as several system
components that install, verify and update `.pkg` flat packages:

  - `PackageKit.framework` - private framework
    (`/System/Library/PrivateFrameworks/PackageKit.framework`) that
    parses flat packages into install operations (extract, run
    scripts, verify signature, shove from the staging sandbox).
  - `pkgbuild(1)`      - build a component package from a root
                         directory (`Sources/pkgbuild`).
  - `productbuild(1)`  - build a product/distribution archive from
                         component packages (`Sources/productbuild`).
  - `installd(8)`        - daemon processing third-party packages (TODO).
  - `system_installd(8)` - daemon processing Apple-signed packages
                           with SIP-protected writes (TODO).
  - `softwareupdated(8)` - system update orchestration (TODO).

## Why clean-room

Apple's PackageKit sources are proprietary and no reference source
exists.  The implementation therefore starts from black-box behavior
of the system oracles (`/usr/bin/pkgbuild`, `/usr/bin/productbuild`,
`pkgutil`) plus published security research (CVE-2019-8561 and
friends), with the goal of being function-identical -- ideally
byte-identical output -- so it can serve as a drop-in replacement
on LibreDarwin without breaking the system.

Compliance is proven against the system tools: for a given input,
our archives must be accepted by `pkgutil` and produce the same
PackageInfo/Payload/Bom structure the system tools emit.

## Delegation (current v1)

The xar writer (`xar.c`) is self-contained so archives are produced
in-tree, but two well-fiddly formats are delegated to the system
until a native implementation lands:

  - Payload cpio copy-out -> `cpio -o -H odc` (same byte layout as
    `find <dir> -print | cpio -o -H odoc | gzip`);
  - BOM generation        -> `mkbom(1)` (the BomCmds sibling project
    owns the native BOM store; it can be linked in later);
  - product archives      -> `xar --compression none` for the
    component rollup in `productbuild`.

## Layout

    Sources/pkgbuild/       the pkgbuild command
    Sources/productbuild/   the productbuild command
    Sources/PackageKit/     PackageKit.framework (TODO)
    Sources/installd/       installd(8) (TODO)
    Sources/system_installd/ system_installd(8) (TODO)
    Sources/softwareupdated/ softwareupdated(8) (TODO)
    make/                   per-config build flags (release/debug/asan)

## Building

    make            # builds pkgbuild and productbuild (release)
    make test       # smoke test
    make CONFIG=debug
    make install    # binaries -> $(PREFIX)/bin

    # Both make dialects are supported:
    make ...        # GNU make
    bmake ...       # BSD make

    # Alternative build system (Xcode):
    xcodebuild -project PackageKit.xcodeproj -target pkgbuild build
    xcodebuild -project PackageKit.xcodeproj -target productbuild build

## License

BSD 3-Clause, Copyright (C) 2026 LibreDarwin.  See LICENSE.
