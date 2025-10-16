use std::{borrow::Cow, io::Read};

use flate2::{
    Compression,
    bufread::{ZlibDecoder, ZlibEncoder},
};
use libsla_sys::sys;
use sleigh_config::processor_x86::PSPEC_X86_64 as PROCESSOR_SPEC;
use sleigh_config::processor_x86::SLA_X86_64 as SLEIGH_SPEC;

use crate::*;

struct LoadImageImpl(Vec<u8>);

impl InstructionLoader for LoadImageImpl {
    fn load_instruction_bytes(&self, data: &VarnodeData) -> std::result::Result<Vec<u8>, String> {
        let start: usize = data.address.offset.try_into().expect("invalid offset");
        if start >= self.0.len() {
            return Err("Requested fill outside image".to_string());
        }

        // Never exceed image
        let end = usize::min(start + data.size, self.0.len());
        Ok(self.0[start..end].to_vec())
    }
}

#[test]
pub fn addr_space_type() -> Result<()> {
    assert_eq!(
        AddressSpaceType::from(sys::spacetype::IPTR_IOP),
        AddressSpaceType::PcodeOp
    );
    assert_eq!(
        AddressSpaceType::from(sys::spacetype::IPTR_CONSTANT),
        AddressSpaceType::Constant
    );
    assert_eq!(
        AddressSpaceType::from(sys::spacetype::IPTR_PROCESSOR),
        AddressSpaceType::Processor
    );
    assert_eq!(
        AddressSpaceType::from(sys::spacetype::IPTR_JOIN),
        AddressSpaceType::Join
    );
    assert_eq!(
        AddressSpaceType::from(sys::spacetype::IPTR_FSPEC),
        AddressSpaceType::FuncCallSpecs
    );
    assert_eq!(
        AddressSpaceType::from(sys::spacetype::IPTR_INTERNAL),
        AddressSpaceType::Internal
    );
    assert_eq!(
        AddressSpaceType::from(sys::spacetype::IPTR_SPACEBASE),
        AddressSpaceType::BaseRegister
    );

    Ok(())
}

#[test]
fn build_sla() -> Result<()> {
    // Confirm the original spec builds successfully
    let sleigh = GhidraSleigh::builder()
        .processor_spec(PROCESSOR_SPEC)?
        .build(SLEIGH_SPEC)?;
    verify_sleigh(sleigh);
    Ok(())
}

#[test]
fn build_sla_recompressed() -> Result<()> {
    const SLA_VERSION: u8 = 4;
    const HEADER_SIZE: usize = 4;

    assert!(SLEIGH_SPEC.len() > HEADER_SIZE);
    assert_eq!(SLEIGH_SPEC[0], b's');
    assert_eq!(SLEIGH_SPEC[1], b'l');
    assert_eq!(SLEIGH_SPEC[2], b'a');
    assert_eq!(SLEIGH_SPEC[3], SLA_VERSION);

    // Decompress input
    let mut decoder = ZlibDecoder::new(&SLEIGH_SPEC[4..]);
    let mut decoded = Vec::new();
    decoder
        .read_to_end(&mut decoded)
        .expect("failed to decode zlib compressed sla spec data");
    assert!(!decoded.is_empty(), "decoded data should not be empty");

    // Recompress input
    let mut encoder = ZlibEncoder::new(std::io::Cursor::new(decoded), Compression::fast());
    let mut compressed_data = Vec::with_capacity(4096);
    encoder
        .read_to_end(&mut compressed_data)
        .expect("failed to compress data");

    let mut test_spec = Vec::with_capacity(compressed_data.len() + HEADER_SIZE);
    test_spec.push(b's');
    test_spec.push(b'l');
    test_spec.push(b'a');
    test_spec.push(SLA_VERSION);
    test_spec.append(&mut compressed_data);

    // Confirm the recompressed spec with header builds successfully
    let sleigh = GhidraSleigh::builder()
        .processor_spec(PROCESSOR_SPEC)?
        .build(test_spec)?;
    verify_sleigh(sleigh);
    Ok(())
}

#[test]
fn build_raw_sla() -> Result<()> {
    const SLA_VERSION: u8 = 4;
    const HEADER_SIZE: usize = 4;

    assert!(SLEIGH_SPEC.len() > HEADER_SIZE);
    assert_eq!(SLEIGH_SPEC[0], b's');
    assert_eq!(SLEIGH_SPEC[1], b'l');
    assert_eq!(SLEIGH_SPEC[2], b'a');
    assert_eq!(SLEIGH_SPEC[3], SLA_VERSION);

    // Decompress input
    let mut decoder = ZlibDecoder::new(&SLEIGH_SPEC[4..]);
    let mut decoded = Vec::new();
    decoder
        .read_to_end(&mut decoded)
        .expect("failed to decode zlib compressed sla spec data");
    assert!(!decoded.is_empty(), "decoded data should not be empty");

    let sleigh = GhidraSleigh::builder()
        .processor_spec(PROCESSOR_SPEC)?
        .sla_encoding(SlaDataEncoding::Raw)
        .build(&decoded)?;
    verify_sleigh(sleigh);
    Ok(())
}

#[test]
fn test_pcode() -> Result<()> {
    const NUM_INSTRUCTIONS: usize = 7;
    let load_image =
        LoadImageImpl(b"\x55\x48\x89\xe5\x89\x7d\xfc\x8b\x45\xfc\x0f\xaf\xc0\x5d\xc3".to_vec());
    let sleigh = GhidraSleigh::builder()
        .processor_spec(PROCESSOR_SPEC)?
        .build(SLEIGH_SPEC)?;
    let mut offset = 0;
    for _ in 0..NUM_INSTRUCTIONS {
        let address = Address {
            offset,
            address_space: sleigh.default_code_space(),
        };

        let response = sleigh
            .disassemble_pcode(&load_image, address)
            .expect("Failed to decode instruction");
        offset += response.origin.size as u64;
    }
    assert_eq!(offset, 15, "Expected 15 bytes to be decoded");
    Ok(())
}

#[test]
fn test_assembly() -> Result<()> {
    let load_image =
        LoadImageImpl(b"\x55\x48\x89\xe5\x89\x7d\xfc\x8b\x45\xfc\x01\xc0\x5d\xc3".to_vec());
    let sleigh = GhidraSleigh::builder()
        .processor_spec(PROCESSOR_SPEC)?
        .build(SLEIGH_SPEC)?;
    let mut offset = 0;
    let expected = vec![
        ("ram".to_string(), 0, "PUSH".to_string(), "RBP".to_string()),
        (
            "ram".to_string(),
            1,
            "MOV".to_string(),
            "RBP,RSP".to_string(),
        ),
        (
            "ram".to_string(),
            4,
            "MOV".to_string(),
            "dword ptr [RBP + -0x4],EDI".to_string(),
        ),
        (
            "ram".to_string(),
            7,
            "MOV".to_string(),
            "EAX,dword ptr [RBP + -0x4]".to_string(),
        ),
        (
            "ram".to_string(),
            10,
            "ADD".to_string(),
            "EAX,EAX".to_string(),
        ),
        ("ram".to_string(), 12, "POP".to_string(), "RBP".to_string()),
        ("ram".to_string(), 13, "RET".to_string(), "".to_string()),
    ];

    for expected_entry in expected {
        let address = Address {
            offset,
            address_space: sleigh.default_code_space(),
        };

        let response = sleigh
            .disassemble_native(&load_image, address)
            .expect("Failed to decode instruction");
        let instruction = &response.instruction;
        assert_eq!(instruction.address.address_space.name, expected_entry.0);
        assert_eq!(instruction.address.offset, expected_entry.1);
        assert_eq!(instruction.mnemonic, expected_entry.2);
        assert_eq!(instruction.body, expected_entry.3);
        println!(
            "{}:{:016x} | {} {}",
            expected_entry.0, expected_entry.1, expected_entry.2, expected_entry.3
        );
        offset += response.origin.size as u64;
    }

    Ok(())
}

#[test]
pub fn register_from_name() -> Result<()> {
    let sleigh = GhidraSleigh::builder()
        .processor_spec(PROCESSOR_SPEC)?
        .build(SLEIGH_SPEC)?;
    let rax = sleigh.register_from_name("RAX").expect("invalid register");
    assert_eq!(rax.address.address_space.name, "register");
    assert_eq!(rax.address.offset, 0);
    assert_eq!(rax.size, 8);
    assert_eq!(sleigh.register_name(&rax), Some("RAX".to_string()));
    Ok(())
}

#[test]
pub fn register_name_of_non_register() -> Result<()> {
    let sleigh = GhidraSleigh::builder()
        .processor_spec(PROCESSOR_SPEC)?
        .build(SLEIGH_SPEC)?;
    let mut register = sleigh
        .register_from_name("RAX")
        .expect("RAX should be a valid register");

    // Change offset to something absurd. Make sure not to trigger the overflow check
    // so that this request will actually go to Ghidra
    register.address.offset = u64::MAX - register.size as u64;

    let result = sleigh.register_name(&register);
    assert!(result.is_none(), "{result:?} should be None");
    Ok(())
}

#[test]
pub fn register_name_of_overflowing_non_register() -> Result<()> {
    let sleigh = GhidraSleigh::builder()
        .processor_spec(PROCESSOR_SPEC)?
        .build(SLEIGH_SPEC)?;
    let mut register = sleigh
        .register_from_name("RAX")
        .expect("RAX should be a valid register");

    // Note that the lookup will perform offset + size without overflow checks
    // There is a guard in our impl against this before calling Ghidra.
    //
    // See ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/sleighbase.cc
    register.address.offset = u64::MAX;

    let result = sleigh.register_name(&register);
    assert!(result.is_none(), "{result:?} should be None");
    Ok(())
}

#[test]
pub fn invalid_register_name() -> Result<()> {
    let sleigh = GhidraSleigh::builder()
        .processor_spec(PROCESSOR_SPEC)?
        .build(SLEIGH_SPEC)?;
    let invalid_register_name = "invalid_register";
    let err = sleigh
        .register_from_name(invalid_register_name)
        .expect_err(&format!(
            "register '{invalid_register_name}' should be invalid"
        ));

    let expected_message: Cow<'static, str> =
        Cow::Owned(format!("failed to get register {invalid_register_name}"));
    match err {
        Error::DependencyError { message, .. } => {
            assert_eq!(message, expected_message);
        }
        _ => panic!("Expected dependency error, got {err:?}"),
    }

    Ok(())
}

#[test]
pub fn insufficient_data() -> Result<()> {
    let load_image = LoadImageImpl(b"\x00".to_vec());
    let sleigh = GhidraSleigh::builder()
        .processor_spec(PROCESSOR_SPEC)?
        .build(SLEIGH_SPEC)?;
    let offset = 0;
    let address = Address {
        offset,
        address_space: sleigh.default_code_space(),
    };

    let err = sleigh
        .disassemble_native(&load_image, address)
        .expect_err("Expected decoding error");
    println!("{err:?}");

    assert!(matches!(err, Error::InsufficientData { .. }));

    Ok(())
}

#[test]
pub fn invalid_instruction() -> Result<()> {
    let load_image = LoadImageImpl(std::iter::repeat_n(0xFF, 16).collect());
    let sleigh = GhidraSleigh::builder()
        .processor_spec(PROCESSOR_SPEC)?
        .build(SLEIGH_SPEC)?;
    let offset = 0;
    let address = Address {
        offset,
        address_space: sleigh.default_code_space(),
    };

    let err = sleigh
        .disassemble_native(&load_image, address)
        .expect_err("Expected decoding error");
    println!("{err:?}");

    assert!(matches!(
        err,
        Error::DependencyError {
            message: Cow::Borrowed("failed to decode instruction"),
            ..
        }
    ));

    Ok(())
}

#[test]
fn all_register_names() -> Result<()> {
    let sleigh = GhidraSleigh::builder()
        .processor_spec(PROCESSOR_SPEC)?
        .build(SLEIGH_SPEC)?;
    let expected_name = ["RAX", "EAX", "AX", "AL"];
    for (i, (reg, name)) in sleigh.register_name_map().iter().take(4).enumerate() {
        assert_eq!(
            reg.address.offset, 0,
            "address offset should be 0 for {name}: {reg:?}"
        );
        assert_eq!(name, expected_name[i]);
    }
    Ok(())
}

#[test]
fn multiple_sleigh_data_sharing() -> Result<()> {
    let sleigh1 = GhidraSleigh::builder()
        .processor_spec(PROCESSOR_SPEC)?
        .build(SLEIGH_SPEC)?;
    let sleigh2 = GhidraSleigh::builder()
        .processor_spec(PROCESSOR_SPEC)?
        .build(SLEIGH_SPEC)?;
    for (reg, name) in &sleigh1.register_name_map() {
        // Sanity check to ensure sleigh1 correctly identifies this as a register
        assert_eq!(name, &sleigh1.register_name(reg).unwrap());

        // Even though the reg varnode is from sleigh1, it should still be recognized by sleigh2
        assert_eq!(name, &sleigh2.register_name(reg).unwrap());
    }
    Ok(())
}

fn verify_sleigh(sleigh: GhidraSleigh) {
    // 0x55 = PUSH RBP
    let loader = LoadImageImpl(vec![0x55]);
    let address = Address::new(sleigh.default_code_space(), 0);
    let disassembly = sleigh
        .disassemble_native(&loader, address)
        .expect("disassembly should succeed");

    let instruction = &disassembly.instruction;
    assert_eq!(instruction.mnemonic, "PUSH");
    assert_eq!(instruction.body, "RBP");
}
