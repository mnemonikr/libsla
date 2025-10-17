use crate::*;

fn test_round_trip<T>(value: &T)
where
    T: serde::Serialize + std::fmt::Debug,
    for<'de> T: serde::Deserialize<'de>,
    for<'a> &'a T: PartialEq,
{
    let serialized = serde_json::to_value(value)
        .unwrap_or_else(|err| panic!("failed to serialize value {value:?}: {err}"));
    let deserialized = serde_json::from_value::<T>(serialized)
        .unwrap_or_else(|err| panic!("failed to deserialize value {value:?}: {err}"));

    assert_eq!(value, &deserialized);
}

#[test]
fn op_code() {
    let values = [
        OpCode::Copy,
        OpCode::Load,
        OpCode::Store,
        OpCode::Branch,
        OpCode::BranchConditional,
        OpCode::BranchIndirect,
        OpCode::Call,
        OpCode::CallIndirect,
        OpCode::Return,
        OpCode::Piece,
        OpCode::Subpiece,
        OpCode::Popcount,
        OpCode::LzCount,
        OpCode::Bool(BoolOp::Negate),
        OpCode::Int(IntOp::Add),
        OpCode::Float(FloatOp::Equal),
        OpCode::Pseudo(PseudoOp::CallOther),
        OpCode::Analysis(AnalysisOp::MultiEqual),
        OpCode::Unknown(-42),
    ];

    for value in values {
        test_round_trip(&value);
    }
}

#[test]
fn bool_op() {
    let values = [BoolOp::Negate, BoolOp::And, BoolOp::Or, BoolOp::Xor];

    for value in values {
        test_round_trip(&value);
    }
}

#[test]
fn int_sign() {
    let values = [IntSign::Signed, IntSign::Unsigned];

    for value in values {
        test_round_trip(&value);
    }
}

#[test]
fn int_op() {
    let values = [
        IntOp::Add,
        IntOp::Negate,
        IntOp::Subtract,
        IntOp::Multiply,
        IntOp::Divide(IntSign::Unsigned),
        IntOp::Remainder(IntSign::Unsigned),
        IntOp::Equal,
        IntOp::NotEqual,
        IntOp::LessThan(IntSign::Unsigned),
        IntOp::LessThanOrEqual(IntSign::Unsigned),
        IntOp::Extension(IntSign::Unsigned),
        IntOp::Carry(IntSign::Unsigned),
        IntOp::Borrow,
        IntOp::ShiftLeft,
        IntOp::ShiftRight(IntSign::Unsigned),
        IntOp::Bitwise(BoolOp::Negate),
    ];

    for value in values {
        test_round_trip(&value);
    }
}

#[test]
fn float_op() {
    let values = [
        FloatOp::NotEqual,
        FloatOp::LessThan,
        FloatOp::LessThanOrEqual,
        FloatOp::IsNaN,
        FloatOp::Add,
        FloatOp::Subtract,
        FloatOp::Multiply,
        FloatOp::Divide,
        FloatOp::Negate,
        FloatOp::AbsoluteValue,
        FloatOp::SquareRoot,
        FloatOp::IntToFloat,
        FloatOp::FloatToFloat,
        FloatOp::Truncate,
        FloatOp::Ceiling,
        FloatOp::Floor,
        FloatOp::Round,
    ];

    for value in values {
        test_round_trip(&value);
    }
}

#[test]
fn pseudo_op() {
    let values = [
        PseudoOp::CallOther,
        PseudoOp::ConstantPoolRef,
        PseudoOp::New,
    ];

    for value in values {
        test_round_trip(&value);
    }
}

#[test]
fn analysis_op() {
    let values = [
        AnalysisOp::MultiEqual,
        AnalysisOp::CopyIndirect,
        AnalysisOp::PointerAdd,
        AnalysisOp::PointerSubcomponent,
        AnalysisOp::Cast,
        AnalysisOp::Insert,
        AnalysisOp::Extract,
        AnalysisOp::SegmentOp,
    ];

    for value in values {
        test_round_trip(&value);
    }
}

#[test]
fn address_space_id() {
    for id in [0, 1, 42, usize::MAX - 1, usize::MAX] {
        let value = AddressSpaceId::new(id);
        test_round_trip(&value);
    }
}

#[test]
fn address_space_type() {
    let values = [
        AddressSpaceType::Constant,
        AddressSpaceType::Processor,
        AddressSpaceType::BaseRegister,
        AddressSpaceType::Internal,
        AddressSpaceType::FuncCallSpecs,
        AddressSpaceType::PcodeOp,
        AddressSpaceType::Join,
    ];

    for value in values {
        test_round_trip(&value);
    }
}

fn constant_address_space(size: usize) -> AddressSpace {
    AddressSpace {
        id: AddressSpaceId::new(42),
        name: "test-address-space".into(),
        word_size: size,
        address_size: size,
        space_type: AddressSpaceType::Constant,
        big_endian: false,
    }
}

#[test]
fn address() {
    for offset in [u64::MIN, u64::MAX, 0, 1, 42] {
        let value = Address::new(constant_address_space(32), offset);
        test_round_trip(&value);
    }
}

fn test_address(addr: u64) -> Address {
    let address_space = AddressSpace {
        id: AddressSpaceId::new(42),
        name: "test-address-space".into(),
        word_size: 32,
        address_size: 32,
        space_type: AddressSpaceType::Processor,
        big_endian: false,
    };

    Address::new(address_space, addr)
}

#[test]
fn varnode_data() {
    for (i, size) in [1, 2, 4, 8, 16, 32, 64].iter().enumerate() {
        let value = VarnodeData::new(test_address(42_000 * i as u64), *size);
        test_round_trip(&value);
    }
}

fn test_instruction() -> PcodeInstruction {
    PcodeInstruction {
        address: test_address(42),
        op_code: OpCode::Load,
        inputs: vec![VarnodeData::new(
            Address::new(constant_address_space(32), 42),
            32,
        )],
        output: Some(VarnodeData::new(test_address(42_000), 32)),
    }
}

fn test_asm_instruction() -> AssemblyInstruction {
    AssemblyInstruction {
        address: test_address(42),
        mnemonic: "TEST".into(),
        body: "TEST foo 42".into(),
    }
}

#[test]
fn pcode_instruction() {
    let value = test_instruction();
    test_round_trip(&value);
}

#[test]
fn assembly_instruction() {
    let value = test_asm_instruction();
    test_round_trip(&value);
}

#[test]
fn pcode_disassembly() {
    let value = PcodeDisassembly {
        instructions: vec![test_instruction(), test_instruction()],
        origin: VarnodeData::new(test_address(42_000), 42),
    };
    test_round_trip(&value);
}

#[test]
fn native_disassembly() {
    let value = NativeDisassembly {
        instruction: test_asm_instruction(),
        origin: VarnodeData::new(test_address(42_000), 42),
    };
    test_round_trip(&value);
}
