# Overview

This crate provides Rust bindings to the Sleigh library libsla found in [NSA's Ghidra](https://github.com/NationalSecurityAgency/ghidra),
which disassembles processor instructions into p-code. This enables binary analysis programs to
analyze arbitrary programs by targeting p-code instead of specific instruction set architectures.

# Latest Changes

See [change log](./CHANGELOG.md) for latest changes.

# Configuration

Building a Sleigh instance requires a _compiled sleigh specification_ (.sla) and a
_processor specification_ (.pspec). These can be obtained from the
[sleigh-config](https://crates.io/crates/sleigh-config) crate.

Processor specification files are responsible for filling in context data defined in sla files. For
example, `addrsize` is variable context defined in the x86 sla file. The x86-64 pspec defines this
as `2` for 64-bit addressing while the x86 pspec defines this as `1` for 32-bit addressing. Note the
sla file is responsible for interpreting the meaning of these values.

## Custom Sleigh Specification

Custom sleigh specification files can be compiled from Rust using the
[sleigh-compiler](https://crates.io/crates/sleigh-compiler) crate. Alternatively the original
compiler can be built from the
[Ghidra decompiler source](https://github.com/NationalSecurityAgency/ghidra/blob/stable/Ghidra/Features/Decompiler/src/decompile/cpp)
using `make sleigh_opt`.

# Example

Disassemble bytes into native assembly instructions.

```rust
let sleigh = GhidraSleigh::builder()
    .processor_spec(sleigh_config::processor_x86::PSPEC_X86_64)?
    .build(sleigh_config::processor_x86::SLA_X86_64)?;

// PUSH RBP instruction is the byte 0x55.
let instructions = InstructionBytes::new(vec![0x55]);

// InstructionBytes is a simple byte loader that does not model multiple address spaces.
// However an address space is required, so for simplicity use the default code space.
let address_space = sleigh.default_code_space();

// Start disassembly from the first byte (index 0)
let instruction_address = Address::new(address_space, 0);

// Confirming this is indeed PUSH RBP.
let native_disassembly = sleigh.disassemble_native(&instructions, instruction_address)?;
assert_eq!(native_disassembly.instruction.mnemonic, "PUSH");
assert_eq!(native_disassembly.instruction.body, "RBP");
```

Disassemble bytes into pcode instructions. Pcode instructions can be used for program modeling.

```rust
let sleigh = GhidraSleigh::builder()
    .processor_spec(sleigh_config::processor_x86::PSPEC_X86_64)?
    .build(sleigh_config::processor_x86::SLA_X86_64)?;

// PUSH RBP
let instructions = InstructionBytes::new(vec![0x55]);
let instruction_address = Address::new(sleigh.default_code_space(), 0);
let pcode_disassembly = sleigh.disassemble_pcode(&instructions, instruction_address)?;
let pcode_instructions = pcode_disassembly.instructions;

assert_eq!(pcode_instructions.len(), 3, "There should be 3 pcode instructions");

// Copy RBP into a temporary
let copy_destination = pcode_instructions[0].output.as_ref().unwrap();
assert_eq!(pcode_instructions[0].op_code, OpCode::Copy);
assert_eq!(sleigh.register_name(&pcode_instructions[0].inputs[0]).unwrap(), "RBP");

// Subtract 8 bytes from RSP
assert_eq!(pcode_instructions[1].op_code, OpCode::Int(IntOp::Subtract));
assert_eq!(sleigh.register_name(&pcode_instructions[1].inputs[0]).unwrap(), "RSP");
assert_eq!(pcode_instructions[1].inputs[1].address.offset, 8);

// Store temporary (RBP) into memory address pointed to by RSP
assert_eq!(pcode_instructions[2].op_code, OpCode::Store);
assert_eq!(sleigh.register_name(&pcode_instructions[2].inputs[1]).unwrap(), "RSP");
assert_eq!(&pcode_instructions[2].inputs[2], copy_destination);
```
