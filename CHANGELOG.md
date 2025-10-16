## Unreleased

### Added

* Support for serializing libsla structures using serde

### Fixed

* `AddressSpace` from another Sleigh instance is now properly recognized.

## [v1.0.0](https://github.com/mnemonikr/libsla/tree/v1.0.0)

### Changed

* `LoadImage` trait renamed to `InstructionLoader`.
* `disassemble_native` returns a single instruction instead of a singleton list.
* `GhidraSleighBuilder` sla parsing simplified. Internally no longer supports `libsla-sys` XML decoding.

## [v0.4.4](https://github.com/mnemonikr/libsla/tree/v0.4.4)

Minor update moving code out of symbolic-pcode workspace and into its own repository

### Changed

* Updated README.md to link to this change log

## [v0.4.3](https://github.com/mnemonikr/symbolic-pcode/tree/libsla-0.4.3)

### Added

* Support for fuzzing `libsla-sys`
* New raw sla encoding format which does not include compression or data header

## [v0.4.2](https://github.com/mnemonikr/symbolic-pcode/tree/libsla-0.4.2)

### Changed

* Updated README.md to reflect release of the [sleigh-config](https://crates.io/crates/sleigh-config)
crate. This crate removes the need to manually compile Ghidra `.slaspec` files, which in most cases
should eliminate the need to reference the Ghidra repository.

## [v0.4.1](https://github.com/mnemonikr/symbolic-pcode/tree/libsla-0.4.1)

### Added

* Added an alternative `build` method to `GhidraSleighBuilder` to enable building with sla file contents directly. This limitation was introduced during the upgrade to Ghidra 11.4.

## [v0.4.0](https://github.com/mnemonikr/symbolic-pcode/tree/libsla-0.4.0)

### Changed

* Upgraded to Ghidra 11.4.
* Extracted internal `sys` module to its own `libsla-sys` crate.

## [v0.3.1](https://github.com/mnemonikr/symbolic-pcode/tree/libsla-0.3.1)

### Changed

* Updated documentation regarding compilation of `.sla` files. Can now build `.sla` files from Rust using [sleigh-compiler](https://crates.io/crates/sleigh-compiler) crate.
* Upgraded `thiserror` from `1` to `2`

## [v0.3.0](https://github.com/mnemonikr/symbolic-pcode/tree/libsla-0.3.0)

### Added

* `Sleigh::register_name`: Get the name for a register identified by `VarnodeData`.
* `Sleigh::register_name_map`: Get a mapping of all registers as `VarnodeData` to their respective
names.
* Implemented `PartialOrd` and `Ord` on `VarnodeData` and dependent types to support ordering in
`register_name_map`.

### Changed

* `DependencyError::source` must now implement `Send` and `Sync`. This is required to convert
`Error` to the error reporting type of other reporting frameworks such as `eyre`.
* `Debug` implementations for `Address` and `AddressSpaceId` to use hex values. For Ghidra the
internal `AddressSpaceId` is actually the virtual address of the `AddressSpace` C++ structure.

## [v0.2.0](https://github.com/mnemonikr/symbolic-pcode/tree/libsla-0.2.0)

### Changed

* Replaced `GhidraSleigh::new` with `GhidraSleigh::builder` to improve construction ergonomics. The
necessary objects required to construct `GhidraSleigh` (`.pspec` and `.sla` files) must be provided
before it is possible to instantiate the object.

### Fixed

* Various Rust clippy lints

## [v0.1.3](https://github.com/mnemonikr/symbolic-pcode/tree/libsla-0.1.3)

### Fixed

* Only publish relevant Ghidra files when publishing crate

## [v0.1.2](https://github.com/mnemonikr/symbolic-pcode/tree/libsla-0.1.2)

### Fixed

* Crate publishing mistake

## [v0.1.1](https://github.com/mnemonikr/symbolic-pcode/tree/libsla-0.1.1)

### Added

* README.md

## [v0.1.0](https://github.com/mnemonikr/symbolic-pcode/tree/libsla-0.1.0)

Initial release!
