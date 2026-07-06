use super::*;

const EH_VADDR: u64 = 0x10_000;

/// Builds a minimal ELF64 image containing one PT_LOAD segment and an
/// `.eh_frame` section with the given bytes at [`EH_VADDR`].
fn build_elf(eh_frame: &[u8], machine: u16) -> Vec<u8> {
    let mut image = vec![0u8; 64];
    image[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    image[4] = 2; // ELFCLASS64
    image[5] = 1; // little endian
    image[18..20].copy_from_slice(&machine.to_le_bytes());

    // One PT_LOAD program header at offset 64.
    let phoff = 64u64;
    let mut phdr = vec![0u8; 56];
    phdr[0..4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    phdr[8..16].copy_from_slice(&0u64.to_le_bytes()); // file offset
    phdr[16..24].copy_from_slice(&0x1000u64.to_le_bytes()); // vaddr
    phdr[32..40].copy_from_slice(&4096u64.to_le_bytes()); // filesz
    image.extend_from_slice(&phdr);

    let eh_offset = image.len() as u64;
    image.extend_from_slice(eh_frame);

    let shstrtab = b"\0.eh_frame\0.shstrtab\0";
    let shstrtab_offset = image.len() as u64;
    image.extend_from_slice(shstrtab);

    let shoff = image.len() as u64;
    let mut sections = vec![0u8; 64]; // null section
    let mut eh_section = vec![0u8; 64];
    eh_section[0..4].copy_from_slice(&1u32.to_le_bytes()); // name offset
    eh_section[4..8].copy_from_slice(&1u32.to_le_bytes()); // SHT_PROGBITS
    eh_section[16..24].copy_from_slice(&EH_VADDR.to_le_bytes());
    eh_section[24..32].copy_from_slice(&eh_offset.to_le_bytes());
    eh_section[32..40].copy_from_slice(&(eh_frame.len() as u64).to_le_bytes());
    sections.extend_from_slice(&eh_section);
    let mut str_section = vec![0u8; 64];
    str_section[0..4].copy_from_slice(&11u32.to_le_bytes());
    str_section[4..8].copy_from_slice(&3u32.to_le_bytes()); // SHT_STRTAB
    str_section[24..32].copy_from_slice(&shstrtab_offset.to_le_bytes());
    str_section[32..40].copy_from_slice(&(shstrtab.len() as u64).to_le_bytes());
    sections.extend_from_slice(&str_section);
    image.extend_from_slice(&sections);

    image[32..40].copy_from_slice(&phoff.to_le_bytes());
    image[40..48].copy_from_slice(&shoff.to_le_bytes());
    image[54..56].copy_from_slice(&56u16.to_le_bytes());
    image[56..58].copy_from_slice(&1u16.to_le_bytes());
    image[58..60].copy_from_slice(&64u16.to_le_bytes());
    image[60..62].copy_from_slice(&3u16.to_le_bytes());
    image[62..64].copy_from_slice(&2u16.to_le_bytes());
    image
}

/// Wraps entry content in the length-prefixed `.eh_frame` framing.
fn entry(content: &[u8]) -> Vec<u8> {
    let mut bytes = (content.len() as u32).to_le_bytes().to_vec();
    bytes.extend_from_slice(content);
    bytes
}

fn x86_64_cie(initial_instructions: &[u8]) -> Vec<u8> {
    let mut content = 0u32.to_le_bytes().to_vec(); // CIE id
    content.push(1); // version
    content.extend_from_slice(b"zR\0");
    content.push(0x01); // code alignment 1
    content.push(0x78); // data alignment -8
    content.push(16); // return address register
    content.push(0x01); // augmentation data length
    content.push(0x1b); // FDE encoding: pcrel | sdata4
    content.extend_from_slice(initial_instructions);
    entry(&content)
}

fn aarch64_cie(initial_instructions: &[u8]) -> Vec<u8> {
    let mut content = 0u32.to_le_bytes().to_vec();
    content.push(1);
    content.extend_from_slice(b"zR\0");
    content.push(0x01);
    content.push(0x78); // data alignment -8
    content.push(30); // return address register (x30)
    content.push(0x01);
    content.push(0x1b);
    content.extend_from_slice(initial_instructions);
    entry(&content)
}

/// Appends an FDE for `[pc_begin, pc_begin + pc_range)` to an eh_frame
/// buffer whose CIE starts at offset 0.
fn push_fde(eh_frame: &mut Vec<u8>, pc_begin: u64, pc_range: u32, instructions: &[u8]) {
    let content_start = eh_frame.len() + 4;
    let cie_pointer = content_start as u32; // distance back to CIE at 0
    let pc_field_vaddr = EH_VADDR + content_start as u64 + 4;
    let pc_delta = (pc_begin as i64 - pc_field_vaddr as i64) as i32;

    let mut content = cie_pointer.to_le_bytes().to_vec();
    content.extend_from_slice(&pc_delta.to_le_bytes());
    content.extend_from_slice(&(pc_range as i32).to_le_bytes());
    content.push(0x00); // augmentation data length
    content.extend_from_slice(instructions);
    eh_frame.extend_from_slice(&entry(&content));
}

const FUNC: u64 = 0x40_000;

#[test]
fn parses_x86_64_prologue_rows() {
    // Typical prologue: CFA=rsp+8 with RA at CFA-8; after `push rbp`
    // CFA=rsp+16 and rbp saved at CFA-16; then CFA switches to rbp+16.
    let mut eh = x86_64_cie(&[0x0c, 0x07, 0x08, 0x90, 0x01]);
    push_fde(
        &mut eh,
        FUNC,
        0x40,
        &[
            0x41, // advance_loc 1
            0x0e, 0x10, // def_cfa_offset 16
            0x86, 0x02, // offset rbp, 2 (-16)
            0x43, // advance_loc 3
            0x0d, 0x06, // def_cfa_register rbp
        ],
    );
    let table = ElfUnwindTable::parse(&build_elf(&eh, EM_X86_64));
    assert_eq!(table.machine(), EM_X86_64);
    assert!(!table.truncated());

    let row = table.lookup(FUNC).expect("entry row");
    assert_eq!(row.cfa, CfaRule::SpOffset(8));
    assert_eq!(row.ra, RaRule::CfaOffset(-8));
    assert_eq!(row.fp, FpRule::Preserved);

    let row = table.lookup(FUNC + 1).expect("post-push row");
    assert_eq!(row.cfa, CfaRule::SpOffset(16));
    assert_eq!(row.fp, FpRule::CfaOffset(-16));

    let row = table.lookup(FUNC + 0x3f).expect("body row");
    assert_eq!(row.cfa, CfaRule::FpOffset(16));
    assert_eq!(row.ra, RaRule::CfaOffset(-8));
}

#[test]
fn lookup_outside_fde_range_is_none() {
    let mut eh = x86_64_cie(&[0x0c, 0x07, 0x08, 0x90, 0x01]);
    push_fde(&mut eh, FUNC, 0x10, &[]);
    let table = ElfUnwindTable::parse(&build_elf(&eh, EM_X86_64));

    assert!(table.lookup(FUNC).is_some());
    assert!(table.lookup(FUNC + 0x0f).is_some());
    assert!(table.lookup(FUNC + 0x10).is_none());
    assert!(table.lookup(FUNC - 1).is_none());
}

#[test]
fn parses_aarch64_leaf_and_saved_lr_rows() {
    // aarch64: RA defaults to the link register until an explicit store.
    let mut eh = aarch64_cie(&[0x0c, 0x1f, 0x00]); // def_cfa sp+0
    push_fde(
        &mut eh,
        FUNC,
        0x40,
        &[
            0x44, // advance_loc 4
            0x0e, 0x20, // def_cfa_offset 32
            0x9e, 0x02, // offset x30, 2 (-16)
            0x9d, 0x04, // offset x29, 4 (-32)
        ],
    );
    let table = ElfUnwindTable::parse(&build_elf(&eh, EM_AARCH64));

    let row = table.lookup(FUNC).expect("leaf row");
    assert_eq!(row.cfa, CfaRule::SpOffset(0));
    assert_eq!(row.ra, RaRule::LinkRegister);

    let row = table.lookup(FUNC + 4).expect("saved row");
    assert_eq!(row.cfa, CfaRule::SpOffset(32));
    assert_eq!(row.ra, RaRule::CfaOffset(-16));
    assert_eq!(row.fp, FpRule::CfaOffset(-32));
}

#[test]
fn cfa_expression_becomes_explicit_unsupported_row() {
    let mut eh = x86_64_cie(&[0x0c, 0x07, 0x08, 0x90, 0x01]);
    push_fde(
        &mut eh,
        FUNC,
        0x20,
        &[
            0x41, // advance_loc 1
            0x0f, 0x02, 0x77, 0x08, // def_cfa_expression, 2-byte block
        ],
    );
    let table = ElfUnwindTable::parse(&build_elf(&eh, EM_X86_64));

    assert_eq!(
        table.lookup(FUNC).expect("entry row").cfa,
        CfaRule::SpOffset(8)
    );
    assert_eq!(
        table.lookup(FUNC + 1).expect("expression row").cfa,
        CfaRule::Unsupported
    );
}

#[test]
fn remember_and_restore_state_round_trips() {
    let mut eh = x86_64_cie(&[0x0c, 0x07, 0x08, 0x90, 0x01]);
    push_fde(
        &mut eh,
        FUNC,
        0x30,
        &[
            0x0a, // remember_state
            0x41, // advance_loc 1
            0x0e, 0x40, // def_cfa_offset 64
            0x41, // advance_loc 1
            0x0b, // restore_state
        ],
    );
    let table = ElfUnwindTable::parse(&build_elf(&eh, EM_X86_64));

    assert_eq!(
        table.lookup(FUNC + 1).expect("modified row").cfa,
        CfaRule::SpOffset(64)
    );
    assert_eq!(
        table.lookup(FUNC + 2).expect("restored row").cfa,
        CfaRule::SpOffset(8)
    );
}

#[test]
fn undefined_return_address_marks_outermost_frame() {
    let mut eh = x86_64_cie(&[0x0c, 0x07, 0x08, 0x07, 0x10]); // def_cfa; undefined r16
    push_fde(&mut eh, FUNC, 0x10, &[]);
    let table = ElfUnwindTable::parse(&build_elf(&eh, EM_X86_64));
    assert_eq!(table.lookup(FUNC).expect("row").ra, RaRule::Undefined);
}

#[test]
fn multiple_fdes_stay_sorted_and_isolated() {
    let mut eh = x86_64_cie(&[0x0c, 0x07, 0x08, 0x90, 0x01]);
    push_fde(&mut eh, FUNC + 0x100, 0x10, &[0x41, 0x0e, 0x20]);
    push_fde(&mut eh, FUNC, 0x10, &[]);
    let table = ElfUnwindTable::parse(&build_elf(&eh, EM_X86_64));

    assert_eq!(table.lookup(FUNC).expect("first").cfa, CfaRule::SpOffset(8));
    assert!(table.lookup(FUNC + 0x20).is_none());
    assert_eq!(
        table.lookup(FUNC + 0x101).expect("second").cfa,
        CfaRule::SpOffset(32)
    );
}

#[test]
fn adjacent_fdes_keep_the_second_fdes_entry_row() {
    // FDE1 ends exactly where FDE2 begins; the gap terminator must not
    // shadow FDE2's entry rules.
    let mut eh = x86_64_cie(&[0x0c, 0x07, 0x08, 0x90, 0x01]);
    push_fde(&mut eh, FUNC, 0x10, &[]);
    push_fde(&mut eh, FUNC + 0x10, 0x10, &[0x41, 0x0e, 0x20]);
    let table = ElfUnwindTable::parse(&build_elf(&eh, EM_X86_64));

    let row = table.lookup(FUNC + 0x10).expect("second fde entry row");
    assert_eq!(row.cfa, CfaRule::SpOffset(8));
    let row = table.lookup(FUNC + 0x11).expect("second fde body row");
    assert_eq!(row.cfa, CfaRule::SpOffset(32));
    assert!(table.lookup(FUNC + 0x20).is_none());
}

#[test]
fn malformed_images_yield_empty_tables_without_panicking() {
    assert!(ElfUnwindTable::parse(&[]).is_empty());
    assert!(ElfUnwindTable::parse(&[0x7f, b'E', b'L', b'F']).is_empty());
    assert!(ElfUnwindTable::parse(&vec![0xff; 4096]).is_empty());

    // A valid container with garbage eh_frame bytes.
    let table = ElfUnwindTable::parse(&build_elf(&[0xde, 0xad, 0xbe, 0xef], EM_X86_64));
    assert!(table.is_empty());

    // Truncate a valid image at every prefix; no panics allowed.
    let mut eh = x86_64_cie(&[0x0c, 0x07, 0x08, 0x90, 0x01]);
    push_fde(&mut eh, FUNC, 0x40, &[0x41, 0x0e, 0x10]);
    let image = build_elf(&eh, EM_X86_64);
    for len in 0..image.len() {
        let _ = ElfUnwindTable::parse(&image[..len]);
    }
}

#[test]
fn unknown_machine_yields_empty_table() {
    let mut eh = x86_64_cie(&[0x0c, 0x07, 0x08]);
    push_fde(&mut eh, FUNC, 0x10, &[]);
    assert!(ElfUnwindTable::parse(&build_elf(&eh, 40 /* EM_ARM */)).is_empty());
}

#[test]
fn parses_load_segments_for_bias_computation() {
    let eh = x86_64_cie(&[0x0c, 0x07, 0x08]);
    let segments = parse_load_segments(&build_elf(&eh, EM_X86_64));
    assert_eq!(
        segments,
        vec![LoadSegment {
            vaddr: 0x1000,
            file_offset: 0,
            file_size: 4096,
        }]
    );
    assert!(parse_load_segments(&[1, 2, 3]).is_empty());
}

#[test]
fn arbitrary_byte_mutations_never_panic() {
    let mut eh = x86_64_cie(&[0x0c, 0x07, 0x08, 0x90, 0x01]);
    push_fde(&mut eh, FUNC, 0x40, &[0x41, 0x0e, 0x10, 0x86, 0x02]);
    let image = build_elf(&eh, EM_X86_64);
    // Deterministic single-byte corruptions across the image.
    for position in 0..image.len() {
        for value in [0x00, 0x7f, 0x80, 0xff] {
            let mut corrupted = image.clone();
            corrupted[position] = value;
            let table = ElfUnwindTable::parse(&corrupted);
            let _ = table.lookup(FUNC + 1);
            let _ = parse_load_segments(&corrupted);
        }
    }
}
