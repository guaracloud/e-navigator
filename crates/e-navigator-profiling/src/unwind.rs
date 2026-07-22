//! DWARF/CFI unwind-table construction from ELF `.eh_frame` data.
//!
//! Parses the call-frame-information subset needed for stack unwinding into
//! flat, pc-sorted rows an eBPF program can binary-search. The supported subset
//! covers CFA as a signed offset from the stack or frame pointer, plus the
//! return address and frame pointer as CFA-relative slots. Rules this subset
//! cannot express (DWARF expressions, exotic CFA registers) become
//! explicit `Unsupported` rows so an unwinder stops with accounting
//! instead of fabricating frames. Parsing never panics on malformed
//! input; anything unreadable yields an empty table or a skipped FDE.

/// ELF machine id for x86-64.
pub const EM_X86_64: u16 = 62;
/// ELF machine id for AArch64.
pub const EM_AARCH64: u16 = 183;

/// Upper bound on rows retained per module table. Large shared objects
/// produce tens of thousands of rows; the bound keeps memory and eBPF
/// map budgets predictable. Overflow is reported, never silent.
pub const MAX_UNWIND_ROWS: usize = 1 << 20;

const MAX_CFI_STACK_DEPTH: usize = 8;
const MAX_ROWS_PER_FDE: usize = 512;

/// How the canonical frame address is recovered for a pc range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CfaRule {
    /// CFA = stack pointer + offset.
    SpOffset(i32),
    /// CFA = frame pointer + offset.
    FpOffset(i32),
    /// The producer used a rule outside the supported subset.
    Unsupported,
    /// Terminator for a gap after an FDE; no unwind information here.
    Invalid,
}

/// How the caller's return address is recovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaRule {
    /// Stored at CFA + offset.
    CfaOffset(i32),
    /// Still live in the link register (AArch64 leaf frames).
    LinkRegister,
    /// Explicitly undefined: the outermost frame; unwinding ends here.
    Undefined,
    /// A rule outside the supported subset.
    Unsupported,
}

/// How the caller's frame pointer is recovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FpRule {
    /// Stored at CFA + offset.
    CfaOffset(i32),
    /// Not saved in this range; the caller's value is still live.
    Preserved,
    /// A rule outside the supported subset.
    Unsupported,
}

/// One unwind row: the rules in force from `pc` (link-time virtual
/// address) until the next row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnwindRow {
    pub pc: u64,
    pub cfa: CfaRule,
    pub ra: RaRule,
    pub fp: FpRule,
}

/// A parsed, pc-sorted unwind table for one ELF image.
#[derive(Debug, Default, Clone)]
pub struct ElfUnwindTable {
    rows: Vec<UnwindRow>,
    machine: u16,
    truncated: bool,
}

impl ElfUnwindTable {
    /// Parses `.eh_frame` rows from an ELF64 image. Returns an empty
    /// table when the image has no usable unwind information.
    pub fn parse(image: &[u8]) -> Self {
        Self::parse_bounded(image, MAX_UNWIND_ROWS)
    }

    /// Parses at most `max_rows` unwind rows from an ELF64 image.
    ///
    /// This is intended for collectors whose downstream unwind-table storage
    /// is smaller than [`MAX_UNWIND_ROWS`]. Bounding construction here avoids
    /// retaining or transiently allocating rows that can never be installed.
    /// A zero bound yields an empty table. [`Self::truncated`] reports when the
    /// input contained more usable rows than the supplied budget.
    pub fn parse_bounded(image: &[u8], max_rows: usize) -> Self {
        if max_rows == 0 {
            return Self::default();
        }
        parse_eh_frame_table(image, max_rows.min(MAX_UNWIND_ROWS)).unwrap_or_default()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// ELF `e_machine` of the parsed image.
    pub fn machine(&self) -> u16 {
        self.machine
    }

    /// True when parsing stopped at [`MAX_UNWIND_ROWS`] and later FDEs
    /// were dropped.
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    pub fn rows(&self) -> &[UnwindRow] {
        &self.rows
    }

    /// Finds the row governing a link-time virtual address, or `None`
    /// when the address falls outside every FDE range.
    pub fn lookup(&self, pc: u64) -> Option<&UnwindRow> {
        let index = match self.rows.binary_search_by(|row| row.pc.cmp(&pc)) {
            Ok(index) => index,
            Err(0) => return None,
            Err(index) => index - 1,
        };
        let row = &self.rows[index];
        (row.cfa != CfaRule::Invalid).then_some(row)
    }
}

/// A PT_LOAD segment, retained so a loader can translate runtime
/// mappings into link-time virtual addresses (load bias).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadSegment {
    pub vaddr: u64,
    pub file_offset: u64,
    pub file_size: u64,
}

/// Parses the PT_LOAD program headers of an ELF64 image. Returns an
/// empty list on malformed input.
pub fn parse_load_segments(image: &[u8]) -> Vec<LoadSegment> {
    parse_load_segments_inner(image).unwrap_or_default()
}

fn parse_load_segments_inner(image: &[u8]) -> Option<Vec<LoadSegment>> {
    let elf = ElfReader::new(image)?;
    let header_offset = elf.read_u64(32)? as usize;
    let entry_size = usize::from(elf.read_u16(54)?);
    let count = usize::from(elf.read_u16(56)?);
    if entry_size < 56 || count == 0 || count > 128 {
        return None;
    }
    const PT_LOAD: u32 = 1;
    let mut segments = Vec::new();
    for index in 0..count {
        let header = header_offset.checked_add(index.checked_mul(entry_size)?)?;
        if elf.read_u32(header)? != PT_LOAD {
            continue;
        }
        segments.push(LoadSegment {
            file_offset: elf.read_u64(header + 8)?,
            vaddr: elf.read_u64(header + 16)?,
            file_size: elf.read_u64(header + 32)?,
        });
    }
    Some(segments)
}

struct ElfReader<'a> {
    image: &'a [u8],
    little_endian: bool,
}

impl<'a> ElfReader<'a> {
    fn new(image: &'a [u8]) -> Option<Self> {
        const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
        const ELFCLASS64: u8 = 2;
        if image.len() < 64 || image[..4] != ELF_MAGIC || image[4] != ELFCLASS64 {
            return None;
        }
        Some(Self {
            image,
            little_endian: image[5] == 1,
        })
    }

    fn read_u16(&self, offset: usize) -> Option<u16> {
        let bytes = self.image.get(offset..offset.checked_add(2)?)?;
        let array = [bytes[0], bytes[1]];
        Some(if self.little_endian {
            u16::from_le_bytes(array)
        } else {
            u16::from_be_bytes(array)
        })
    }

    fn read_u32(&self, offset: usize) -> Option<u32> {
        let bytes = self.image.get(offset..offset.checked_add(4)?)?;
        let array = [bytes[0], bytes[1], bytes[2], bytes[3]];
        Some(if self.little_endian {
            u32::from_le_bytes(array)
        } else {
            u32::from_be_bytes(array)
        })
    }

    fn read_u64(&self, offset: usize) -> Option<u64> {
        let bytes = self.image.get(offset..offset.checked_add(8)?)?;
        let mut array = [0u8; 8];
        array.copy_from_slice(bytes);
        Some(if self.little_endian {
            u64::from_le_bytes(array)
        } else {
            u64::from_be_bytes(array)
        })
    }
}

/// Per-architecture DWARF register numbers for the subset we track.
#[derive(Debug, Clone, Copy)]
struct ArchRegisters {
    stack_pointer: u64,
    frame_pointer: u64,
    return_address: u64,
    /// The return address lives in a link register when no explicit
    /// rule stores it on the stack (AArch64).
    link_register_default: bool,
}

fn arch_registers(machine: u16) -> Option<ArchRegisters> {
    match machine {
        EM_X86_64 => Some(ArchRegisters {
            stack_pointer: 7,
            frame_pointer: 6,
            return_address: 16,
            link_register_default: false,
        }),
        EM_AARCH64 => Some(ArchRegisters {
            stack_pointer: 31,
            frame_pointer: 29,
            return_address: 30,
            link_register_default: true,
        }),
        _ => None,
    }
}

fn parse_eh_frame_table(image: &[u8], max_rows: usize) -> Option<ElfUnwindTable> {
    let elf = ElfReader::new(image)?;
    let machine = elf.read_u16(18)?;
    let registers = arch_registers(machine)?;

    let (section_offset, section_vaddr, section_size) = find_eh_frame_section(&elf)?;
    let section = image.get(section_offset..section_offset.checked_add(section_size)?)?;

    let mut cies = std::collections::BTreeMap::new();
    let mut rows: Vec<UnwindRow> = Vec::new();
    let mut truncated = false;
    let mut cursor = 0usize;

    while cursor + 4 <= section.len() {
        let entry_start = cursor;
        let mut length = u32::from_le_bytes([
            section[cursor],
            section[cursor + 1],
            section[cursor + 2],
            section[cursor + 3],
        ]) as usize;
        cursor += 4;
        if length == 0 {
            // Zero terminator.
            break;
        }
        if length == 0xffff_ffff {
            // 64-bit DWARF length; read the real length.
            let bytes = section.get(cursor..cursor + 8)?;
            let mut array = [0u8; 8];
            array.copy_from_slice(bytes);
            length = usize::try_from(u64::from_le_bytes(array)).ok()?;
            cursor += 8;
        }
        let content_start = cursor;
        let content_end = cursor.checked_add(length)?;
        if content_end > section.len() {
            break;
        }
        let content = &section[cursor..content_end];
        if content.len() < 4 {
            cursor = content_end;
            continue;
        }
        let id = u32::from_le_bytes([content[0], content[1], content[2], content[3]]);
        if id == 0 {
            if let Some(cie) = parse_cie(&content[4..]) {
                cies.insert(entry_start, cie);
            }
        } else {
            // FDE: id is the distance back from this field to its CIE.
            let cie_start = content_start.checked_sub(id as usize);
            if let Some(cie_start) = cie_start
                && let Some(cie) = cies.get(&cie_start)
            {
                if rows.len() >= max_rows {
                    truncated = true;
                    break;
                }
                let fde_field_vaddr = section_vaddr.checked_add(cursor as u64)?.checked_add(4)?;
                parse_fde(&content[4..], cie, &registers, fde_field_vaddr, &mut rows);
                if rows.len() > max_rows {
                    rows.truncate(max_rows);
                    truncated = true;
                    break;
                }
            }
        }
        cursor = content_end;
    }

    if rows.is_empty() {
        return None;
    }
    // Adjacent FDEs place a gap terminator at exactly the next FDE's
    // first pc; sort real rows ahead of terminators so dedup keeps the
    // real rule for that address.
    rows.sort_by_key(|row| (row.pc, row.cfa == CfaRule::Invalid));
    rows.dedup_by_key(|row| row.pc);
    Some(ElfUnwindTable {
        rows,
        machine,
        truncated,
    })
}

fn find_eh_frame_section(elf: &ElfReader<'_>) -> Option<(usize, u64, usize)> {
    let section_header_offset = elf.read_u64(40)? as usize;
    let section_entry_size = usize::from(elf.read_u16(58)?);
    let section_count = usize::from(elf.read_u16(60)?);
    let names_index = usize::from(elf.read_u16(62)?);
    if section_entry_size < 64 || section_count == 0 || section_count > 65_000 {
        return None;
    }
    let names_header =
        section_header_offset.checked_add(names_index.checked_mul(section_entry_size)?)?;
    let names_offset = elf.read_u64(names_header + 24)? as usize;
    let names_size = elf.read_u64(names_header + 32)? as usize;
    let names = elf
        .image
        .get(names_offset..names_offset.checked_add(names_size)?)?;

    for index in 0..section_count {
        let header = section_header_offset.checked_add(index.checked_mul(section_entry_size)?)?;
        let name_offset = elf.read_u32(header)? as usize;
        let name = names.get(name_offset..)?;
        if !name.starts_with(b".eh_frame\0") {
            continue;
        }
        let vaddr = elf.read_u64(header + 16)?;
        let offset = elf.read_u64(header + 24)? as usize;
        let size = elf.read_u64(header + 32)? as usize;
        return Some((offset, vaddr, size));
    }
    None
}

#[derive(Debug, Clone)]
struct Cie {
    code_alignment: u64,
    data_alignment: i64,
    return_address_register: u64,
    fde_pointer_encoding: u8,
    augmentation_has_data: bool,
    initial_instructions: Vec<u8>,
}

fn parse_cie(content: &[u8]) -> Option<Cie> {
    let mut cursor = Cursor::new(content);
    let version = cursor.read_u8()?;
    if version != 1 && version != 3 {
        return None;
    }
    let augmentation = cursor.read_c_string()?;
    if augmentation.contains(&b'e') {
        // "eh" legacy augmentation with an extra word; unsupported.
        return None;
    }
    let code_alignment = cursor.read_uleb128()?;
    let data_alignment = cursor.read_sleb128()?;
    let return_address_register = if version == 1 {
        u64::from(cursor.read_u8()?)
    } else {
        cursor.read_uleb128()?
    };

    let mut fde_pointer_encoding = encodings::ABSPTR;
    let augmentation_has_data = augmentation.first() == Some(&b'z');
    if augmentation_has_data {
        let data_len = cursor.read_uleb128()? as usize;
        let data = cursor.take(data_len)?;
        let mut data_cursor = Cursor::new(data);
        for flag in &augmentation[1..] {
            match flag {
                b'R' => fde_pointer_encoding = data_cursor.read_u8()?,
                b'P' => {
                    let encoding = data_cursor.read_u8()?;
                    data_cursor.skip_encoded_pointer(encoding)?;
                }
                b'L' => {
                    let _lsda_encoding = data_cursor.read_u8()?;
                }
                b'S' | b'B' | b'G' => {}
                _ => return None,
            }
        }
    }

    Some(Cie {
        code_alignment,
        data_alignment,
        return_address_register,
        fde_pointer_encoding,
        augmentation_has_data,
        initial_instructions: cursor.rest().to_vec(),
    })
}

fn parse_fde(
    content: &[u8],
    cie: &Cie,
    registers: &ArchRegisters,
    fde_field_vaddr: u64,
    rows: &mut Vec<UnwindRow>,
) -> Option<()> {
    let mut cursor = Cursor::new(content);
    let pc_begin = cursor.read_encoded_pointer(cie.fde_pointer_encoding, fde_field_vaddr)?;
    let pc_range = cursor.read_encoded_pointer(
        cie.fde_pointer_encoding & 0x0f,
        // The range is always absolute regardless of the base modifier.
        0,
    )?;
    if cie.augmentation_has_data {
        let augmentation_len = cursor.read_uleb128()? as usize;
        cursor.take(augmentation_len)?;
    }

    let mut interpreter = CfiInterpreter::new(cie, registers, pc_begin);
    interpreter.run(&cie.initial_instructions)?;
    interpreter.initial_state_defined();
    interpreter.run(cursor.rest())?;
    interpreter.finish(pc_begin.checked_add(pc_range)?, rows);
    Some(())
}

#[derive(Debug, Clone, Copy)]
struct RegisterState {
    cfa: CfaRule,
    ra: RaRule,
    fp: FpRule,
}

struct CfiInterpreter<'a> {
    cie: &'a Cie,
    registers: &'a ArchRegisters,
    location: u64,
    state: RegisterState,
    initial: RegisterState,
    stack: Vec<RegisterState>,
    pending: Vec<UnwindRow>,
}

impl<'a> CfiInterpreter<'a> {
    fn new(cie: &'a Cie, registers: &'a ArchRegisters, pc_begin: u64) -> Self {
        let state = RegisterState {
            cfa: CfaRule::Unsupported,
            ra: if registers.link_register_default {
                RaRule::LinkRegister
            } else {
                RaRule::Unsupported
            },
            fp: FpRule::Preserved,
        };
        Self {
            cie,
            registers,
            location: pc_begin,
            state,
            initial: state,
            stack: Vec::new(),
            pending: Vec::new(),
        }
    }

    fn initial_state_defined(&mut self) {
        self.initial = self.state;
    }

    fn emit_row(&mut self) {
        if self.pending.len() >= MAX_ROWS_PER_FDE {
            return;
        }
        let row = UnwindRow {
            pc: self.location,
            cfa: self.state.cfa,
            ra: self.state.ra,
            fp: self.state.fp,
        };
        match self.pending.last_mut() {
            Some(last) if last.pc == row.pc => *last = row,
            _ => self.pending.push(row),
        }
    }

    fn advance(&mut self, delta: u64) {
        self.emit_row();
        self.location = self.location.saturating_add(delta);
    }

    fn set_register_rule(&mut self, register: u64, rule: Option<i64>) {
        // `None` marks an unsupported rule for that register.
        if register == self.registers.return_address || register == self.cie.return_address_register
        {
            self.state.ra = match rule {
                Some(offset) => match i32::try_from(offset) {
                    Ok(offset) => RaRule::CfaOffset(offset),
                    Err(_) => RaRule::Unsupported,
                },
                None => RaRule::Unsupported,
            };
        } else if register == self.registers.frame_pointer {
            self.state.fp = match rule {
                Some(offset) => match i32::try_from(offset) {
                    Ok(offset) => FpRule::CfaOffset(offset),
                    Err(_) => FpRule::Unsupported,
                },
                None => FpRule::Unsupported,
            };
        }
    }

    fn restore_register(&mut self, register: u64) {
        if register == self.registers.return_address || register == self.cie.return_address_register
        {
            self.state.ra = self.initial.ra;
        } else if register == self.registers.frame_pointer {
            self.state.fp = self.initial.fp;
        }
    }

    fn run(&mut self, instructions: &[u8]) -> Option<()> {
        let mut cursor = Cursor::new(instructions);
        while let Some(opcode) = cursor.read_u8() {
            match opcode >> 6 {
                1 => {
                    // DW_CFA_advance_loc
                    let delta = u64::from(opcode & 0x3f);
                    self.advance(delta.checked_mul(self.cie.code_alignment)?);
                }
                2 => {
                    // DW_CFA_offset
                    let register = u64::from(opcode & 0x3f);
                    let factored = cursor.read_uleb128()?;
                    let offset = i64::try_from(factored)
                        .ok()?
                        .checked_mul(self.cie.data_alignment)?;
                    self.set_register_rule(register, Some(offset));
                }
                3 => {
                    // DW_CFA_restore
                    self.restore_register(u64::from(opcode & 0x3f));
                }
                _ => self.run_extended(opcode, &mut cursor)?,
            }
        }
        Some(())
    }

    fn run_extended(&mut self, opcode: u8, cursor: &mut Cursor<'_>) -> Option<()> {
        match opcode {
            0x00 => {} // DW_CFA_nop
            0x01 => {
                // DW_CFA_set_loc
                let address =
                    cursor.read_encoded_pointer(self.cie.fde_pointer_encoding & 0x0f, 0)?;
                self.emit_row();
                self.location = address;
            }
            0x02 => {
                let delta = u64::from(cursor.read_u8()?);
                self.advance(delta.checked_mul(self.cie.code_alignment)?);
            }
            0x03 => {
                let delta = u64::from(cursor.read_u16()?);
                self.advance(delta.checked_mul(self.cie.code_alignment)?);
            }
            0x04 => {
                let delta = u64::from(cursor.read_u32()?);
                self.advance(delta.checked_mul(self.cie.code_alignment)?);
            }
            0x05 => {
                // DW_CFA_offset_extended
                let register = cursor.read_uleb128()?;
                let factored = cursor.read_uleb128()?;
                let offset = i64::try_from(factored)
                    .ok()?
                    .checked_mul(self.cie.data_alignment)?;
                self.set_register_rule(register, Some(offset));
            }
            0x06 => {
                let register = cursor.read_uleb128()?;
                self.restore_register(register);
            }
            0x07 => {
                // DW_CFA_undefined: for the return address this marks the
                // outermost frame.
                let register = cursor.read_uleb128()?;
                if register == self.registers.return_address
                    || register == self.cie.return_address_register
                {
                    self.state.ra = RaRule::Undefined;
                } else if register == self.registers.frame_pointer {
                    self.state.fp = FpRule::Unsupported;
                }
            }
            0x08 => {
                // DW_CFA_same_value
                let register = cursor.read_uleb128()?;
                if register == self.registers.return_address
                    || register == self.cie.return_address_register
                {
                    self.state.ra = if self.registers.link_register_default {
                        RaRule::LinkRegister
                    } else {
                        RaRule::Unsupported
                    };
                } else if register == self.registers.frame_pointer {
                    self.state.fp = FpRule::Preserved;
                }
            }
            0x09 => {
                // DW_CFA_register
                let register = cursor.read_uleb128()?;
                let _source = cursor.read_uleb128()?;
                self.set_register_rule(register, None);
            }
            0x0a => {
                if self.stack.len() < MAX_CFI_STACK_DEPTH {
                    self.stack.push(self.state);
                }
            }
            0x0b => {
                if let Some(state) = self.stack.pop() {
                    self.state = state;
                }
            }
            0x0c => {
                // DW_CFA_def_cfa
                let register = cursor.read_uleb128()?;
                let offset = i64::try_from(cursor.read_uleb128()?).ok()?;
                self.state.cfa = self.cfa_rule(register, offset);
            }
            0x0d => {
                // DW_CFA_def_cfa_register keeps the current offset.
                let register = cursor.read_uleb128()?;
                let offset = match self.state.cfa {
                    CfaRule::SpOffset(offset) | CfaRule::FpOffset(offset) => i64::from(offset),
                    CfaRule::Unsupported | CfaRule::Invalid => {
                        self.state.cfa = CfaRule::Unsupported;
                        return Some(());
                    }
                };
                self.state.cfa = self.cfa_rule(register, offset);
            }
            0x0e => {
                // DW_CFA_def_cfa_offset keeps the current register.
                let offset = i64::try_from(cursor.read_uleb128()?).ok()?;
                self.state.cfa = match self.state.cfa {
                    CfaRule::SpOffset(_) => self.offset_rule(offset, false),
                    CfaRule::FpOffset(_) => self.offset_rule(offset, true),
                    CfaRule::Unsupported | CfaRule::Invalid => CfaRule::Unsupported,
                };
            }
            0x0f => {
                // DW_CFA_def_cfa_expression
                let length = cursor.read_uleb128()? as usize;
                cursor.take(length)?;
                self.state.cfa = CfaRule::Unsupported;
            }
            0x10 | 0x16 => {
                // DW_CFA_expression / DW_CFA_val_expression
                let register = cursor.read_uleb128()?;
                let length = cursor.read_uleb128()? as usize;
                cursor.take(length)?;
                self.set_register_rule(register, None);
            }
            0x11 => {
                // DW_CFA_offset_extended_sf
                let register = cursor.read_uleb128()?;
                let factored = cursor.read_sleb128()?;
                let offset = factored.checked_mul(self.cie.data_alignment)?;
                self.set_register_rule(register, Some(offset));
            }
            0x12 => {
                // DW_CFA_def_cfa_sf
                let register = cursor.read_uleb128()?;
                let factored = cursor.read_sleb128()?;
                let offset = factored.checked_mul(self.cie.data_alignment)?;
                self.state.cfa = self.cfa_rule(register, offset);
            }
            0x13 => {
                // DW_CFA_def_cfa_offset_sf
                let factored = cursor.read_sleb128()?;
                let offset = factored.checked_mul(self.cie.data_alignment)?;
                self.state.cfa = match self.state.cfa {
                    CfaRule::SpOffset(_) => self.offset_rule(offset, false),
                    CfaRule::FpOffset(_) => self.offset_rule(offset, true),
                    CfaRule::Unsupported | CfaRule::Invalid => CfaRule::Unsupported,
                };
            }
            0x14 | 0x15 => {
                // DW_CFA_val_offset / DW_CFA_val_offset_sf
                let register = cursor.read_uleb128()?;
                if opcode == 0x14 {
                    cursor.read_uleb128()?;
                } else {
                    cursor.read_sleb128()?;
                }
                self.set_register_rule(register, None);
            }
            0x2e => {
                // DW_CFA_GNU_args_size: no effect on our subset.
                cursor.read_uleb128()?;
            }
            0x2d | 0x2f => {
                // DW_CFA_GNU_window_save / GNU_negative_offset_extended:
                // architecture-specific legacy; treat conservatively.
                self.state.cfa = CfaRule::Unsupported;
            }
            _ => return None,
        }
        Some(())
    }

    fn cfa_rule(&self, register: u64, offset: i64) -> CfaRule {
        let Ok(offset) = i32::try_from(offset) else {
            return CfaRule::Unsupported;
        };
        if register == self.registers.stack_pointer {
            CfaRule::SpOffset(offset)
        } else if register == self.registers.frame_pointer {
            CfaRule::FpOffset(offset)
        } else {
            CfaRule::Unsupported
        }
    }

    fn offset_rule(&self, offset: i64, frame_pointer: bool) -> CfaRule {
        let Ok(offset) = i32::try_from(offset) else {
            return CfaRule::Unsupported;
        };
        if frame_pointer {
            CfaRule::FpOffset(offset)
        } else {
            CfaRule::SpOffset(offset)
        }
    }

    fn finish(mut self, pc_end: u64, rows: &mut Vec<UnwindRow>) {
        self.emit_row();
        rows.append(&mut self.pending);
        // Terminate the range so lookups past this FDE do not reuse its
        // rules unless the next FDE starts exactly at pc_end.
        rows.push(UnwindRow {
            pc: pc_end,
            cfa: CfaRule::Invalid,
            ra: RaRule::Unsupported,
            fp: FpRule::Unsupported,
        });
    }
}

mod encodings {
    pub(super) const ABSPTR: u8 = 0x00;
    pub(super) const OMIT: u8 = 0xff;
    pub(super) const ULEB128: u8 = 0x01;
    pub(super) const UDATA2: u8 = 0x02;
    pub(super) const UDATA4: u8 = 0x03;
    pub(super) const UDATA8: u8 = 0x04;
    pub(super) const SLEB128: u8 = 0x09;
    pub(super) const SDATA2: u8 = 0x0a;
    pub(super) const SDATA4: u8 = 0x0b;
    pub(super) const SDATA8: u8 = 0x0c;
    pub(super) const PCREL: u8 = 0x10;
    pub(super) const INDIRECT: u8 = 0x80;
}

struct Cursor<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    fn rest(&self) -> &'a [u8] {
        &self.data[self.position.min(self.data.len())..]
    }

    fn read_u8(&mut self) -> Option<u8> {
        let byte = *self.data.get(self.position)?;
        self.position += 1;
        Some(byte)
    }

    fn read_u16(&mut self) -> Option<u16> {
        let bytes = self.take(2)?;
        Some(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Option<u32> {
        let bytes = self.take(4)?;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64(&mut self) -> Option<u64> {
        let bytes = self.take(8)?;
        let mut array = [0u8; 8];
        array.copy_from_slice(bytes);
        Some(u64::from_le_bytes(array))
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.position.checked_add(len)?;
        let bytes = self.data.get(self.position..end)?;
        self.position = end;
        Some(bytes)
    }

    fn read_c_string(&mut self) -> Option<Vec<u8>> {
        let rest = self.data.get(self.position..)?;
        let end = rest.iter().position(|byte| *byte == 0)?;
        if end > 32 {
            return None;
        }
        let bytes = rest[..end].to_vec();
        self.position += end + 1;
        Some(bytes)
    }

    fn read_uleb128(&mut self) -> Option<u64> {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = self.read_u8()?;
            if shift >= 64 {
                return None;
            }
            result |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(result);
            }
            shift += 7;
        }
    }

    fn read_sleb128(&mut self) -> Option<i64> {
        let mut result: i64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = self.read_u8()?;
            if shift >= 64 {
                return None;
            }
            result |= i64::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                if shift < 64 && byte & 0x40 != 0 {
                    result |= -1_i64 << shift;
                }
                return Some(result);
            }
        }
    }

    fn read_encoded_pointer(&mut self, encoding: u8, pc_relative_base: u64) -> Option<u64> {
        if encoding == encodings::OMIT {
            return None;
        }
        if encoding & encodings::INDIRECT != 0 {
            // Requires a runtime memory dereference; unsupported.
            return None;
        }
        let value_position = self.position as u64;
        let value = match encoding & 0x0f {
            encodings::ABSPTR | encodings::UDATA8 => self.read_u64()?,
            encodings::ULEB128 => self.read_uleb128()?,
            encodings::UDATA2 => u64::from(self.read_u16()?),
            encodings::UDATA4 => u64::from(self.read_u32()?),
            encodings::SLEB128 => self.read_sleb128()? as u64,
            encodings::SDATA2 => i64::from(self.read_u16()? as i16) as u64,
            encodings::SDATA4 => i64::from(self.read_u32()? as i32) as u64,
            encodings::SDATA8 => self.read_u64()?,
            _ => return None,
        };
        match encoding & 0x70 {
            0x00 => Some(value),
            encodings::PCREL => {
                // pc_relative_base is the virtual address of the start of
                // the field being decoded.
                let base = pc_relative_base.checked_add(value_position)?;
                Some(base.wrapping_add(value))
            }
            _ => None,
        }
    }

    fn skip_encoded_pointer(&mut self, encoding: u8) -> Option<()> {
        if encoding == encodings::OMIT {
            return Some(());
        }
        match encoding & 0x0f {
            encodings::ABSPTR | encodings::UDATA8 | encodings::SDATA8 => {
                self.take(8)?;
            }
            encodings::ULEB128 => {
                self.read_uleb128()?;
            }
            encodings::SLEB128 => {
                self.read_sleb128()?;
            }
            encodings::UDATA2 | encodings::SDATA2 => {
                self.take(2)?;
            }
            encodings::UDATA4 | encodings::SDATA4 => {
                self.take(4)?;
            }
            _ => return None,
        }
        Some(())
    }
}

#[cfg(test)]
mod tests;
