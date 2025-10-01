use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Once;

use libsla_sys::cxx::{CxxVector, UniquePtr, let_cxx_string};

use crate::opcodes::OpCode;
use libsla_sys::api;
use libsla_sys::rust;
use libsla_sys::sys;

/// Tracks whether the one-time initialization required for libsla has been performed
static LIBSLA_INIT: Once = Once::new();

/// Errors returned by this crate. Note that APIs that may pass through FFI boundaries return
/// [String] since those errors are ultimately serialized anyway.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("input invalid: {message}")]
    InvalidInput { message: Cow<'static, str> },

    #[error("insufficient data at varnode {0}")]
    InsufficientData(VarnodeData),

    #[error("dependency error: {message} caused by {source}")]
    DependencyError {
        message: Cow<'static, str>,
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("internal error: {0}")]
    InternalError(String),
}

/// Result returned by Sleigh APIs
pub type Result<T> = std::result::Result<T, Error>;

/// Interface for the Sleigh API. See [GhidraSleigh] for the Ghidra implementation.
pub trait Sleigh {
    /// Get the default address space for code execution
    #[must_use]
    fn default_code_space(&self) -> AddressSpace;

    /// List all available address spaces
    #[must_use]
    fn address_spaces(&self) -> Vec<AddressSpace>;

    /// Get an address space by name (if it exists)
    #[must_use]
    fn address_space_by_name(&self, name: impl AsRef<str>) -> Option<AddressSpace> {
        let name = name.as_ref();
        self.address_spaces()
            .into_iter()
            .find(|addr_space| addr_space.name == name)
    }

    /// Get the [VarnodeData] that represents the named register.
    fn register_from_name(&self, name: impl AsRef<str>) -> Result<VarnodeData>;

    /// Disassemble the instructions at the given address into pcode.
    fn disassemble_pcode(
        &self,
        loader: &dyn InstructionLoader,
        address: Address,
    ) -> Result<PcodeDisassembly>;

    /// Disassemble the instructions at the given address into native assembly instructions.
    fn disassemble_native(
        &self,
        loader: &dyn InstructionLoader,
        address: Address,
    ) -> Result<NativeDisassembly>;

    /// Get the register name for a varnode targeting a register. This will return `None` if the
    /// target is not a valid register.
    fn register_name(&self, target: &VarnodeData) -> Option<String>;

    /// Get a sorted map of registers to register names.
    fn register_name_map(&self) -> BTreeMap<VarnodeData, String>;
}

/// An address is represented by an offset into an address space
#[derive(Ord, PartialOrd, PartialEq, Eq, Clone)]
pub struct Address {
    /// The standard interpretation of the offset is an index into the associated address space.
    /// However, when used in conjunction with the constant address space, the offset is the actual
    /// value. In some contexts this value may be signed, in which case the offset should be
    /// considered an [i64] value.
    pub offset: u64,
    pub address_space: AddressSpace,
}

impl Address {
    pub fn new(address_space: AddressSpace, offset: u64) -> Self {
        Self {
            address_space,
            offset,
        }
    }
}

impl std::fmt::Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Address")
            .field("offset", &format!("{offset:#016x}", offset = &self.offset))
            .field("address_space", &self.address_space)
            .finish()
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{:0width$x}",
            self.address_space,
            self.offset,
            // Each byte is represented by 2 hex characters
            width = 2 * self.address_space.address_size
        )
    }
}

impl From<&sys::Address> for Address {
    fn from(address: &sys::Address) -> Self {
        Self {
            offset: address.offset(),
            address_space: unsafe { &*address.address_space() }.into(),
        }
    }
}

/// A VarnodeData represents the address and size of data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VarnodeData {
    pub address: Address,
    pub size: usize,
}

impl Ord for VarnodeData {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.address.cmp(&other.address) {
            std::cmp::Ordering::Equal => (),
            ord => return ord,
        }

        // Larger size should come first
        other.size.cmp(&self.size)
    }
}

impl PartialOrd for VarnodeData {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Display for VarnodeData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}]#{}", self.address, self.size)
    }
}

impl VarnodeData {
    pub fn new(address: Address, size: usize) -> Self {
        Self { address, size }
    }

    pub fn range(&self) -> std::ops::Range<u64> {
        let offset = self.address.offset * self.address.address_space.word_size as u64;
        let size: u64 = self
            .size
            .try_into()
            .unwrap_or_else(|err| panic!("invalid varnode size {size}: {err}", size = self.size));

        offset..offset + size
    }
}

impl From<&sys::VarnodeData> for VarnodeData {
    fn from(varnode: &sys::VarnodeData) -> Self {
        let size = sys::varnode_size(varnode);
        Self {
            address: sys::varnode_address(varnode).as_ref().unwrap().into(),
            size: size.try_into().unwrap_or_else(|err| {
                panic!("unable to convert Ghidra varnode size: {size}. {err}")
            }),
        }
    }
}

/// Address space identifier for an address space
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AddressSpaceId(usize);

impl std::fmt::Debug for AddressSpaceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AddressSpaceId")
            .field(&format!(
                "{id:#0width$x}",
                id = &self.0,
                width = 2 * std::mem::size_of::<usize>()
            ))
            .finish()
    }
}

impl std::fmt::Display for AddressSpaceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:#0width$x}",
            self.0,
            // Each byte is represented by 2 hex characters
            width = 2 * std::mem::size_of::<usize>()
        )
    }
}

impl AddressSpaceId {
    /// Construct a new address space id
    pub const fn new(id: usize) -> Self {
        Self(id)
    }

    /// Get the raw identifier representing this address space id. This identifier should be
    /// treated as an opaque value.
    pub const fn raw_id(self) -> usize {
        self.0
    }
}

/// Information about an address space
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AddressSpace {
    pub id: AddressSpaceId,
    pub name: Cow<'static, str>,
    pub word_size: usize,
    pub address_size: usize,
    pub space_type: AddressSpaceType,
    pub big_endian: bool,
}

impl AddressSpace {
    pub fn is_constant(&self) -> bool {
        self.space_type == AddressSpaceType::Constant
    }

    /// Creates an address space from a Ghidra address space id.
    ///
    /// # Safety
    ///
    /// The address space id must have originated from the Ghidra library in the current process.
    pub unsafe fn from_ghidra_id(id: AddressSpaceId) -> AddressSpace {
        AddressSpace::from(unsafe { &*(id.0 as *const sys::AddrSpace) })
    }
}

impl std::fmt::Display for AddressSpace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl From<&sys::AddrSpace> for AddressSpace {
    fn from(address_space: &sys::AddrSpace) -> Self {
        Self {
            id: address_space.into(),
            name: Cow::Owned(address_space.name().to_string()),
            word_size: address_space.word_size().try_into().unwrap(),
            address_size: address_space.address_size().try_into().unwrap(),
            space_type: address_space.space_type().into(),
            big_endian: address_space.big_endian(),
        }
    }
}

impl From<&sys::AddrSpace> for AddressSpaceId {
    fn from(address_space: &sys::AddrSpace) -> Self {
        Self::new((address_space as *const _) as usize)
    }
}

/// Types for an [AddressSpace].
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AddressSpaceType {
    /// Special space to represent constants
    Constant,
    /// Normal spaces modelled by processor
    Processor,
    /// addresses = offsets off of base register
    BaseRegister,
    /// Internally managed temporary space
    Internal,
    /// Special internal FuncCallSpecs reference
    FuncCallSpecs,
    /// Special internal PcodeOp reference
    PcodeOp,
    /// Special virtual space to represent split variables
    Join,
}

impl From<sys::spacetype> for AddressSpaceType {
    fn from(space_type: sys::spacetype) -> Self {
        match space_type {
            sys::spacetype::IPTR_CONSTANT => Self::Constant,
            sys::spacetype::IPTR_PROCESSOR => Self::Processor,
            sys::spacetype::IPTR_SPACEBASE => Self::BaseRegister,
            sys::spacetype::IPTR_INTERNAL => Self::Internal,
            sys::spacetype::IPTR_FSPEC => Self::FuncCallSpecs,
            sys::spacetype::IPTR_IOP => Self::PcodeOp,
            sys::spacetype::IPTR_JOIN => Self::Join,
            _ => panic!("Unknown address space type: {space_type:?}"),
        }
    }
}

/// A pcode instruction
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcodeInstruction {
    /// The originating address for this instruction. This information is necessary to include for
    /// the [OpCode::BranchIndirect] operation, which determines the destination address space from
    /// the instruction address space.
    pub address: Address,

    /// The operation this pcode performs. The operation defines the semantics for the inputs and
    /// optional output of this instruction.
    pub op_code: OpCode,

    /// The inputs this pcode operation requires. The semantics for the inputs is determined by
    /// the [OpCode]. For example, the [OpCode::Load] operation requires the first input has an
    /// address in the [AddressSpaceType::Constant] address space, and is interpreted as an address
    /// space identifier for the ultimate address to load. The second input is interpreted as a
    /// pointer to the offset of the address to load, meaning its size must match the target
    /// address space.
    pub inputs: Vec<VarnodeData>,

    /// The output for the pcode operation. The semantics of the output and whether it is expected
    /// is determined by the [OpCode].
    pub output: Option<VarnodeData>,
}

impl std::fmt::Display for PcodeInstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {:?} ", self.address, self.op_code)?;
        if let Some(output) = &self.output {
            write!(f, "{output} <- ")?;
        }

        for input in self.inputs.iter() {
            write!(f, "{input} ")?;
        }

        Ok(())
    }
}

/// A disassembled native assembly instruction
#[derive(Clone, Debug)]
pub struct AssemblyInstruction {
    /// The origin of the assembly instruction
    pub address: Address,

    /// The instruction mnemonic
    pub mnemonic: String,

    /// The body of the instruction
    pub body: String,
}

impl std::fmt::Display for AssemblyInstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{address}] {mnemonic} {body}",
            address = self.address,
            mnemonic = self.mnemonic,
            body = self.body
        )?;
        Ok(())
    }
}

/// Disassembly of an instruction into pcode
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcodeDisassembly {
    /// The disassembled instructions
    pub instructions: Vec<PcodeInstruction>,

    /// The origin of the instructions
    pub origin: VarnodeData,
}

/// Disassembly of an instruction into its native assembly
#[derive(Clone, Debug)]
pub struct NativeDisassembly {
    /// The disassembled instruction
    pub instruction: AssemblyInstruction,

    /// The origin of the instructions
    pub origin: VarnodeData,
}

impl std::fmt::Display for NativeDisassembly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "[{origin}]: {instruction}",
            origin = self.origin,
            instruction = self.instruction,
        )?;

        Ok(())
    }
}

impl std::fmt::Display for PcodeDisassembly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "[{origin}]: {count} instructions",
            origin = self.origin,
            count = self.instructions.len()
        )?;

        for instr in &self.instructions {
            writeln!(f, "{instr}")?;
        }

        Ok(())
    }
}

#[derive(Default)]
struct NativeDisassemblyOutput {
    instruction: Option<AssemblyInstruction>,
}

impl api::AssemblyEmit for NativeDisassemblyOutput {
    fn dump(
        &mut self,
        address: &sys::Address,
        mnemonic: &libsla_sys::cxx::CxxString,
        body: &libsla_sys::cxx::CxxString,
    ) {
        assert!(
            self.instruction.is_none(),
            "native disassembly should dump 1 instruction"
        );

        self.instruction = Some(AssemblyInstruction {
            address: address.into(),
            mnemonic: mnemonic.to_string(),
            body: body.to_string(),
        });
    }
}

#[derive(Default)]
struct PcodeDisassemblyOutput {
    instructions: Vec<PcodeInstruction>,
}

impl api::PcodeEmit for PcodeDisassemblyOutput {
    fn dump(
        &mut self,
        address: &sys::Address,
        op_code: sys::OpCode,
        output_variable: Option<&sys::VarnodeData>,
        input_variables: &CxxVector<sys::VarnodeData>,
    ) {
        self.instructions.push(PcodeInstruction {
            address: address.into(),
            op_code: op_code.into(),
            inputs: input_variables
                .into_iter()
                .map(Into::<VarnodeData>::into)
                .collect(),
            output: output_variable.map(Into::<VarnodeData>::into),
        });
    }
}

/// Wrapper around the public load image API so that it can be converted to the native API.
/// This is required in order to pass a trait object reference down into the native API.
struct InstructionLoaderWrapper<'a>(&'a dyn InstructionLoader);

impl InstructionLoaderWrapper<'_> {
    /// Returns true only if the requested number of instruction bytes are read.
    fn is_readable(&self, varnode: &VarnodeData) -> bool {
        self.0
            .load_instruction_bytes(varnode)
            .is_ok_and(|data| data.len() == varnode.size)
    }
}

impl api::LoadImage for InstructionLoaderWrapper<'_> {
    fn load_fill(
        &self,
        data: &mut [u8],
        address: &sys::Address,
    ) -> std::result::Result<(), String> {
        let varnode = VarnodeData {
            size: data.len(),
            address: address.into(),
        };

        let loaded_data = self.0.load_instruction_bytes(&varnode)?;
        data[..loaded_data.len()].copy_from_slice(&loaded_data);

        Ok(())
    }
}

/// Interface for loading instruction bytes to be disassembled.
pub trait InstructionLoader {
    /// Load instruction bytes from the requested source. If not all of the requested bytes are
    /// available, then the initial sequence of bytes which are available should be returned. For
    /// example, if the caller requests 30 bytes but only the first 10 are available, only those 10
    /// should be returned.
    fn load_instruction_bytes(&self, source: &VarnodeData) -> std::result::Result<Vec<u8>, String>;
}

/// The encoding of the compiled sleigh specification (.slaspec).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum SlaDataEncoding {
    /// Standard .sla encoding. Includes header with appropriate version and zlib compressed data.
    #[default]
    Sla,

    /// Raw encoding. Does not include a header and the data is uncompressed.
    Raw,
}

/// The sleigh or processor specification has not yet been provided
pub enum MissingSpec {}

/// The sleigh or processor specification has been provided
pub enum HasSpec {}

/// Builder for [GhidraSleigh]. The parameter `P` tracks whether the processor specification has
/// been provided.
pub struct GhidraSleighBuilder<P> {
    /// Document store for sleigh and processor specifications
    store: UniquePtr<sys::DocumentStorage>,

    /// The data encoding for the sla specification
    sla_encoding: SlaDataEncoding,

    /// Phantom data for type tracking whether processor specification has been provided
    processor_spec: std::marker::PhantomData<P>,
}

impl Default for GhidraSleighBuilder<MissingSpec> {
    fn default() -> Self {
        // This global libsla initialization is required for parsing sleigh document
        LIBSLA_INIT.call_once(|| {
            sys::initialize_element_id();
            sys::initialize_attribute_id();
        });

        Self {
            store: sys::new_document_storage(),
            sla_encoding: Default::default(),
            processor_spec: Default::default(),
        }
    }
}

impl GhidraSleighBuilder<MissingSpec> {
    /// Use this processor specification for this sleigh instance.
    pub fn processor_spec(mut self, processor_spec: &str) -> Result<GhidraSleighBuilder<HasSpec>> {
        let_cxx_string!(processor_spec = processor_spec);
        sys::parse_document_and_register_root(self.store.pin_mut(), &processor_spec).map_err(
            |err| Error::DependencyError {
                message: Cow::Borrowed("failed to parse processor specification"),
                source: Box::new(err),
            },
        )?;

        Ok(GhidraSleighBuilder::<HasSpec> {
            store: self.store,
            sla_encoding: self.sla_encoding,
            processor_spec: std::marker::PhantomData,
        })
    }
}

impl GhidraSleighBuilder<HasSpec> {
    /// Set the encoding of the sla data. This setting has no effect if building with an XML sleigh
    /// specification file.
    pub fn sla_encoding(self, encoding: SlaDataEncoding) -> Self {
        Self {
            store: self.store,
            sla_encoding: encoding,
            processor_spec: std::marker::PhantomData,
        }
    }

    pub fn build(self, sla: impl AsRef<[u8]>) -> Result<GhidraSleigh> {
        let_cxx_string!(sla = sla);
        let mut sleigh = sys::new_sleigh(sys::new_context_internal());

        let pin = sleigh.pin_mut();

        let init_result = match self.sla_encoding {
            SlaDataEncoding::Sla => pin.initialize_from_sla(&sla),
            SlaDataEncoding::Raw => pin.initialize_from_raw_sla(&sla),
        };

        init_result.map_err(|err| Error::DependencyError {
            message: Cow::Borrowed("failed to initialize Ghidra sleigh"),
            source: Box::new(err),
        })?;

        sleigh
            .pin_mut()
            .parse_processor_config(&self.store)
            .map_err(|err| Error::DependencyError {
                message: Cow::Borrowed("failed to import processor config"),
                source: Box::new(err),
            })?;

        Ok(GhidraSleigh { sleigh })
    }
}

/// Sleigh instance that uses Ghidra libsla for its disassembly.
pub struct GhidraSleigh {
    /// The sleigh object. This object holds a reference to the image loader.
    sleigh: UniquePtr<sys::SleighProxy>,
}

impl GhidraSleigh {
    /// Create a new sleigh builder. Use this to construct a sleigh instance.
    pub fn builder() -> GhidraSleighBuilder<MissingSpec> {
        Default::default()
    }

    /// Convert an address to a system address. Returns `None` if the provided address space cannot
    /// be mapped to a system address space.
    fn sys_address(&self, address: &Address) -> Option<UniquePtr<sys::Address>> {
        // SAFETY: The provided address space has been verified to be safe
        Some(unsafe {
            sys::new_address(
                self.sys_address_space(address.address_space.id)?,
                address.offset,
            )
        })
    }

    /// Creates address space using the given address space id. Returns `None` if the provided id
    /// cannot be mapped to a system address space.
    fn sys_address_space(&self, space_id: AddressSpaceId) -> Option<*mut sys::AddrSpace> {
        let num_spaces = self.sleigh.num_spaces();
        for i in 0..num_spaces {
            let addr_space = self.sleigh.address_space(i);

            // SAFETY: The address space returned here is safe to dereference
            if AddressSpaceId::from(unsafe { &*addr_space }) == space_id {
                return Some(addr_space);
            }
        }

        None
    }
}

impl Sleigh for GhidraSleigh {
    fn default_code_space(&self) -> AddressSpace {
        unsafe { &*self.sleigh.default_code_space() }.into()
    }

    fn address_spaces(&self) -> Vec<AddressSpace> {
        let num_spaces = self.sleigh.num_spaces();
        let mut addr_spaces = Vec::with_capacity(num_spaces as usize);
        for i in 0..num_spaces {
            // SAFETY: Address spaces returned from sleigh are safe to dereference
            let raw_addr_space = unsafe { &*self.sleigh.address_space(i) };
            addr_spaces.push(raw_addr_space.into());
        }
        addr_spaces
    }

    /// Get the register name for a varnode targeting a register. This will return `None` if the
    /// target is not a valid register.
    fn register_name(&self, target: &VarnodeData) -> Option<String> {
        let base = self.sys_address_space(target.address.address_space.id)?;

        // If offset + size overflows then Ghidra can accidentally match a register
        //
        // See getRegisterName in ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/sleighbase.cc
        let _ = target.address.offset.checked_add(target.size as u64)?;

        let register_name = unsafe {
            self.sleigh
                .register_name(base, target.address.offset, target.size as i32)
        };
        let register_name = register_name.to_string();

        if register_name.is_empty() {
            None
        } else {
            Some(register_name)
        }
    }

    fn register_from_name(&self, name: impl AsRef<str>) -> Result<VarnodeData> {
        let_cxx_string!(name = name.as_ref());
        self.sleigh
            .register_from_name(&name)
            .map(VarnodeData::from)
            .map_err(|err| Error::DependencyError {
                message: Cow::Owned(format!("failed to get register {name}")),
                source: Box::new(err),
            })
    }

    fn disassemble_pcode(
        &self,
        loader: &dyn InstructionLoader,
        address: Address,
    ) -> Result<PcodeDisassembly> {
        let sys_address = self.sys_address(&address).expect("invalid address");
        let loader = InstructionLoaderWrapper(loader);
        let rust_loader = rust::RustLoadImage(&loader);
        let mut output = PcodeDisassemblyOutput::default();
        let mut emitter = rust::RustPcodeEmit(&mut output);
        let response = self.sleigh.disassemble_pcode(
            &rust_loader,
            &mut emitter,
            sys_address.as_ref().unwrap(),
        );

        Ok(PcodeDisassembly {
            origin: handle_disassembly_response(response, loader, address)?,
            instructions: output.instructions,
        })
    }

    fn disassemble_native(
        &self,
        loader: &dyn InstructionLoader,
        address: Address,
    ) -> Result<NativeDisassembly> {
        let sys_address = self.sys_address(&address).expect("invalid address");
        let loader = InstructionLoaderWrapper(loader);
        let rust_loader = rust::RustLoadImage(&loader);
        let mut output = NativeDisassemblyOutput::default();
        let mut emitter = rust::RustAssemblyEmit(&mut output);
        let response = self.sleigh.disassemble_native(
            &rust_loader,
            &mut emitter,
            sys_address.as_ref().unwrap(),
        );

        Ok(NativeDisassembly {
            origin: handle_disassembly_response(response, loader, address)?,
            instruction: output.instruction.ok_or_else(|| {
                Error::InternalError("ghidra did not disassemble an instruction".to_owned())
            })?,
        })
    }

    fn register_name_map(&self) -> BTreeMap<VarnodeData, String> {
        self.sleigh
            .all_register_names()
            .into_iter()
            .map(|data| (data.register().into(), data.name().to_string()))
            .collect()
    }
}

/// Construct the origin of the disassembly. This can fail if the disassembly is determined to
/// have originated from invalid data.
fn handle_disassembly_response(
    response: std::result::Result<i32, libsla_sys::cxx::Exception>,
    loader: InstructionLoaderWrapper,
    address: Address,
) -> Result<VarnodeData> {
    let source = VarnodeData {
        address,
        size: num_bytes_disassembled(response)?,
    };

    // Sleigh may attempt to read more bytes than are available to read.
    // Unfortuantely the callback API does not provide any mechanism to
    // inform the caller that only a subset of the requested bytes are valid.
    // Since many ISAs are variable-length instructions, it is possible the
    // valid subset will decode to a valid instruction, and the requested length
    // was an over-estimation.
    //
    // This is a sanity check to determine if the bytes Sleigh used for decoding
    // are all valid.
    if !loader.is_readable(&source) {
        return Err(Error::InsufficientData(source));
    }

    Ok(source)
}

fn num_bytes_disassembled(
    response: std::result::Result<i32, libsla_sys::cxx::Exception>,
) -> Result<usize> {
    let bytes_consumed = response
        .map_err(|err| Error::DependencyError {
            message: Cow::Borrowed("failed to decode instruction"),
            source: Box::new(err),
        })?
        .try_into()
        .map_err(|err| {
            Error::InternalError(format!("instruction origin size is too large: {err}"))
        })?;
    Ok(bytes_consumed)
}
