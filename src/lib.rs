//! This crate includes Rust bindings to the
//! [Ghidra](https://github.com/NationalSecurityAgency/ghidra) SLEIGH library libsla for translating
//! native code to p-code. This allows binary analysis programs to model p-code instead of needing
//! to model each processor architecture separately.
//!
//! ## Examples
//!
//! ### Native Disassembly
//!
//! This example disassembles the `PUSH RBP` x86-64 instruction (byte `0x55`).
//!
//! ```
//! # use crate::libsla::*;
//! # use sleigh_config;
//! # fn main() -> crate::libsla::Result<()> {
//! let sleigh = GhidraSleigh::builder()
//!     .processor_spec(sleigh_config::processor_x86::PSPEC_X86_64)?
//!     .build(sleigh_config::processor_x86::SLA_X86_64)?;
//!
//! // PUSH RBP instruction is the byte 0x55.
//! let instructions = InstructionBytes::new(vec![0x55]);
//!
//! // InstructionBytes is a simple byte loader that does not model multiple address spaces.
//! // However an address space is required, so for simplicity use the default code space.
//! let address_space = sleigh.default_code_space();
//!
//! // Start disassembly from the first byte (index 0)
//! let instruction_address = Address::new(address_space, 0);
//!
//! // Confirming this is indeed PUSH RBP.
//! let native_disassembly = sleigh.disassemble_native(&instructions, instruction_address)?;
//! assert_eq!(native_disassembly.instruction.mnemonic, "PUSH");
//! assert_eq!(native_disassembly.instruction.body, "RBP");
//! # Ok(())
//! # }
//! ```
//! ### Pcode Disassembly
//!
//! This example disassembles the `PUSH RBP` x86-64 instruction (`0x55`) into pcode. The pcode for
//! this instruction is
//!
//! 1. `COPY temp <- RBP`
//! 2. `SUBTRACT RSP <- RSP 0x8`
//! 3. `STORE [RSP] <- temp`
//!
//! ###
//! ```
//! # use crate::libsla::*;
//! # use sleigh_config;
//! # fn main() -> crate::libsla::Result<()> {
//! let sleigh = GhidraSleigh::builder()
//!     .processor_spec(sleigh_config::processor_x86::PSPEC_X86_64)?
//!     .build(sleigh_config::processor_x86::SLA_X86_64)?;
//!
//! // PUSH RBP
//! let instructions = InstructionBytes::new(vec![0x55]);
//! let instruction_address = Address::new(sleigh.default_code_space(), 0);
//! let pcode_disassembly = sleigh.disassemble_pcode(&instructions, instruction_address)?;
//! let pcode_instructions = pcode_disassembly.instructions;
//!
//! assert_eq!(pcode_instructions.len(), 3, "There should be 3 pcode instructions");
//!
//! // Copy RBP into a temporary
//! let copy_destination = pcode_instructions[0].output.as_ref().unwrap();
//! assert_eq!(pcode_instructions[0].op_code, OpCode::Copy);
//! assert_eq!(sleigh.register_name(&pcode_instructions[0].inputs[0]).unwrap(), "RBP");
//!
//! // Subtract 8 bytes from RSP
//! assert_eq!(pcode_instructions[1].op_code, OpCode::Int(IntOp::Subtract));
//! assert_eq!(sleigh.register_name(&pcode_instructions[1].inputs[0]).unwrap(), "RSP");
//! assert_eq!(pcode_instructions[1].inputs[1].address.offset, 8);
//!
//! // Store temporary (RBP) into memory address pointed to by RSP
//! assert_eq!(pcode_instructions[2].op_code, OpCode::Store);
//! assert_eq!(sleigh.register_name(&pcode_instructions[2].inputs[1]).unwrap(), "RSP");
//! assert_eq!(&pcode_instructions[2].inputs[2], copy_destination);
//!
//! # Ok(())
//! # }
//! ```

mod opcodes;
mod sleigh;

pub use opcodes::*;
pub use sleigh::*;

#[cfg(test)]
mod tests;
