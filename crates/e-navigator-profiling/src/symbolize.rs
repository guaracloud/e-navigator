//! Bounded, allocation-frugal symbolization for captured instruction
//! pointers.
//!
//! Symbolization follows the capture-then-resolve split used by production
//! profilers: the privileged agent resolves each instruction pointer to the
//! backing module and a module-relative offset from `/proc/<pid>/maps`, which
//! is enough for a pprof consumer or offline symbol server to recover
//! function names. A best-effort bounded ELF symbol-table lookup fills local
//! function names when the module file is readable, without a DWARF/unwinder
//! dependency in the hot path.

use std::collections::BTreeMap;

const MAX_MAP_ENTRIES: usize = 4096;
const MAX_ELF_SYMBOLS: usize = 200_000;
const MAX_ELF_SYMBOL_NAME_BYTES: usize = 256;

/// One executable memory mapping from `/proc/<pid>/maps`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleMapping {
    pub start: u64,
    pub end: u64,
    /// File offset of the mapping's first byte.
    pub file_offset: u64,
    pub path: String,
}

/// Where a captured instruction pointer resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedLocation {
    pub module: String,
    /// Offset into the module file backing the mapping.
    pub module_offset: u64,
}

/// Executable mappings for one process, ordered by start address.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ProcessModuleMap {
    entries: Vec<ModuleMapping>,
}

impl ProcessModuleMap {
    /// Parses the executable mappings from `/proc/<pid>/maps` text. Only
    /// file-backed, executable mappings are retained; anonymous and
    /// non-executable regions are irrelevant to instruction pointers.
    pub fn parse_maps(contents: &str) -> Self {
        let mut entries = Vec::new();
        for line in contents.lines() {
            if entries.len() >= MAX_MAP_ENTRIES {
                break;
            }
            if let Some(entry) = parse_maps_line(line) {
                entries.push(entry);
            }
        }
        entries.sort_by_key(|entry| entry.start);
        Self { entries }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn mappings(&self) -> &[ModuleMapping] {
        &self.entries
    }

    /// Resolves an absolute instruction pointer to a module and a
    /// module-relative file offset.
    pub fn resolve(&self, ip: u64) -> Option<ResolvedLocation> {
        let index = match self.entries.binary_search_by(|entry| entry.start.cmp(&ip)) {
            Ok(index) => index,
            Err(0) => return None,
            Err(index) => index - 1,
        };
        let entry = &self.entries[index];
        if ip < entry.start || ip >= entry.end {
            return None;
        }
        let module_offset = entry.file_offset.checked_add(ip - entry.start)?;
        Some(ResolvedLocation {
            module: entry.path.clone(),
            module_offset,
        })
    }
}

fn parse_maps_line(line: &str) -> Option<ModuleMapping> {
    // Format: start-end perms offset dev inode pathname
    let mut fields = line.split_whitespace();
    let address_range = fields.next()?;
    let perms = fields.next()?;
    let offset = fields.next()?;
    let _dev = fields.next()?;
    let _inode = fields.next()?;
    let path = fields.collect::<Vec<_>>().join(" ");

    if perms.as_bytes().get(2).is_none_or(|byte| *byte != b'x') {
        return None;
    }
    if path.is_empty() || path.starts_with('[') {
        return None;
    }
    let (start, end) = address_range.split_once('-')?;
    let start = u64::from_str_radix(start, 16).ok()?;
    let end = u64::from_str_radix(end, 16).ok()?;
    let file_offset = u64::from_str_radix(offset, 16).ok()?;
    if end <= start {
        return None;
    }
    Some(ModuleMapping {
        start,
        end,
        file_offset,
        path,
    })
}

/// A bounded ELF64 symbol table mapping code offsets to function names.
#[derive(Debug, Default, Clone)]
pub struct ElfSymbolTable {
    /// Function start offset -> (size, name). Sorted by start offset.
    functions: BTreeMap<u64, (u64, String)>,
}

impl ElfSymbolTable {
    /// Parses `.symtab`/`.dynsym` function symbols from an ELF64 image.
    /// Returns an empty table for anything it cannot safely parse; it never
    /// panics on malformed input.
    pub fn parse(image: &[u8]) -> Self {
        parse_elf64_functions(image).unwrap_or_default()
    }

    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }

    pub fn len(&self) -> usize {
        self.functions.len()
    }

    /// Resolves a module-relative offset to the enclosing function name.
    pub fn resolve(&self, offset: u64) -> Option<&str> {
        let (start, (size, name)) = self.functions.range(..=offset).next_back()?;
        if *size == 0 || offset < start.checked_add(*size)? {
            Some(name.as_str())
        } else {
            None
        }
    }
}

/// Finds the link-time virtual address of a named symbol in an ELF64
/// image, searching `.symtab` and `.dynsym` for any symbol type.
/// Returns `None` on malformed input; never panics.
pub fn find_elf_symbol_address(image: &[u8], name: &str) -> Option<u64> {
    if image.len() < 64 || image[..4] != ELF_MAGIC || image[4] != ELFCLASS64 {
        return None;
    }
    let little_endian = image[5] == 1;
    let read_u16 = |offset: usize| -> Option<u16> {
        let bytes = image.get(offset..offset.checked_add(2)?)?;
        let array = [bytes[0], bytes[1]];
        Some(if little_endian {
            u16::from_le_bytes(array)
        } else {
            u16::from_be_bytes(array)
        })
    };
    let read_u32 = |offset: usize| -> Option<u32> {
        let bytes = image.get(offset..offset.checked_add(4)?)?;
        let array = [bytes[0], bytes[1], bytes[2], bytes[3]];
        Some(if little_endian {
            u32::from_le_bytes(array)
        } else {
            u32::from_be_bytes(array)
        })
    };
    let read_u64 = |offset: usize| -> Option<u64> {
        let bytes = image.get(offset..offset.checked_add(8)?)?;
        let mut array = [0u8; 8];
        array.copy_from_slice(bytes);
        Some(if little_endian {
            u64::from_le_bytes(array)
        } else {
            u64::from_be_bytes(array)
        })
    };

    let section_header_offset = read_u64(40)? as usize;
    let section_entry_size = usize::from(read_u16(58)?);
    let section_count = usize::from(read_u16(60)?);
    if section_entry_size < 64 || section_count == 0 || section_count > 65_000 {
        return None;
    }
    for index in 0..section_count {
        let header = section_header_offset.checked_add(index.checked_mul(section_entry_size)?)?;
        let section_type = read_u32(header + 4)?;
        if section_type != SHT_SYMTAB && section_type != SHT_DYNSYM {
            continue;
        }
        let table_offset = read_u64(header + 24)? as usize;
        let table_size = read_u64(header + 32)? as usize;
        let string_section_index = read_u32(header + 40)? as usize;
        let entry_size = read_u64(header + 56)? as usize;
        if entry_size < 24 || table_size == 0 {
            continue;
        }
        let string_header = section_header_offset
            .checked_add(string_section_index.checked_mul(section_entry_size)?)?;
        let string_offset = read_u64(string_header + 24)? as usize;
        let string_size = read_u64(string_header + 32)? as usize;
        let Some(string_table) = image.get(string_offset..string_offset.checked_add(string_size)?)
        else {
            continue;
        };
        let symbol_count = (table_size / entry_size).min(1_000_000);
        for symbol_index in 0..symbol_count {
            let symbol = table_offset.checked_add(symbol_index.checked_mul(entry_size)?)?;
            let name_offset = read_u32(symbol)? as usize;
            let value = read_u64(symbol + 8)?;
            if value == 0 {
                continue;
            }
            if read_c_string(string_table, name_offset) == Some(name) {
                return Some(value);
            }
        }
    }
    None
}

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const SHT_SYMTAB: u32 = 2;
const SHT_DYNSYM: u32 = 11;
const STT_FUNC: u8 = 2;

fn parse_elf64_functions(image: &[u8]) -> Option<ElfSymbolTable> {
    if image.len() < 64 || image[..4] != ELF_MAGIC || image[4] != ELFCLASS64 {
        return None;
    }
    let little_endian = image[5] == 1;
    let read_u16 = |offset: usize| -> Option<u16> {
        let bytes = image.get(offset..offset + 2)?;
        let array = [bytes[0], bytes[1]];
        Some(if little_endian {
            u16::from_le_bytes(array)
        } else {
            u16::from_be_bytes(array)
        })
    };
    let read_u32 = |offset: usize| -> Option<u32> {
        let bytes = image.get(offset..offset + 4)?;
        let array = [bytes[0], bytes[1], bytes[2], bytes[3]];
        Some(if little_endian {
            u32::from_le_bytes(array)
        } else {
            u32::from_be_bytes(array)
        })
    };
    let read_u64 = |offset: usize| -> Option<u64> {
        let bytes = image.get(offset..offset + 8)?;
        let mut array = [0u8; 8];
        array.copy_from_slice(bytes);
        Some(if little_endian {
            u64::from_le_bytes(array)
        } else {
            u64::from_be_bytes(array)
        })
    };

    let section_header_offset = read_u64(40)? as usize;
    let section_entry_size = usize::from(read_u16(58)?);
    let section_count = usize::from(read_u16(60)?);
    if section_entry_size < 64 || section_count == 0 {
        return None;
    }

    let mut functions = BTreeMap::new();
    for index in 0..section_count {
        let header = section_header_offset.checked_add(index.checked_mul(section_entry_size)?)?;
        let section_type = read_u32(header + 4)?;
        if section_type != SHT_SYMTAB && section_type != SHT_DYNSYM {
            continue;
        }
        let table_offset = read_u64(header + 24)? as usize;
        let table_size = read_u64(header + 32)? as usize;
        let string_section_index = read_u32(header + 40)? as usize;
        let entry_size = read_u64(header + 56)? as usize;
        if entry_size < 24 || table_size == 0 {
            continue;
        }

        let string_header = section_header_offset
            .checked_add(string_section_index.checked_mul(section_entry_size)?)?;
        let string_offset = read_u64(string_header + 24)? as usize;
        let string_size = read_u64(string_header + 32)? as usize;
        let Some(string_table) = image.get(string_offset..string_offset.checked_add(string_size)?)
        else {
            continue;
        };

        let symbol_count = table_size / entry_size;
        for symbol_index in 0..symbol_count {
            if functions.len() >= MAX_ELF_SYMBOLS {
                break;
            }
            let symbol = table_offset.checked_add(symbol_index.checked_mul(entry_size)?)?;
            let name_offset = read_u32(symbol)? as usize;
            let info = *image.get(symbol + 4)?;
            let value = read_u64(symbol + 8)?;
            let size = read_u64(symbol + 16)?;
            if info & 0x0f != STT_FUNC || value == 0 {
                continue;
            }
            let Some(name) = read_c_string(string_table, name_offset) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            functions
                .entry(value)
                .or_insert_with(|| (size, name.to_string()));
        }
    }

    if functions.is_empty() {
        return None;
    }
    Some(ElfSymbolTable { functions })
}

fn read_c_string(table: &[u8], offset: usize) -> Option<&str> {
    let bytes = table.get(offset..)?;
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len())
        .min(MAX_ELF_SYMBOL_NAME_BYTES);
    std::str::from_utf8(&bytes[..end]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAPS: &str = "\
55f000000000-55f000001000 r-xp 00001000 fd:00 100 /usr/bin/app
55f000001000-55f000002000 rw-p 00002000 fd:00 100 /usr/bin/app
7f0000000000-7f0000010000 r-xp 00000000 fd:00 200 /lib/x86_64-linux-gnu/libc.so.6
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0 [stack]
7f0000020000-7f0000021000 r--p 00000000 fd:00 200 /lib/x86_64-linux-gnu/libc.so.6
";

    #[test]
    fn parses_only_executable_file_backed_mappings() {
        let map = ProcessModuleMap::parse_maps(MAPS);
        assert_eq!(map.mappings().len(), 2);
        assert!(
            map.mappings()
                .iter()
                .all(|entry| entry.path.starts_with('/'))
        );
    }

    #[test]
    fn resolves_ip_to_module_offset() {
        let map = ProcessModuleMap::parse_maps(MAPS);
        // 0x55f000000500 is 0x500 into the app text mapping whose file
        // offset is 0x1000, so the module offset is 0x1500.
        let resolved = map.resolve(0x55f000000500).expect("app ip resolves");
        assert_eq!(resolved.module, "/usr/bin/app");
        assert_eq!(resolved.module_offset, 0x1500);

        let libc = map.resolve(0x7f0000000123).expect("libc ip resolves");
        assert_eq!(libc.module, "/lib/x86_64-linux-gnu/libc.so.6");
        assert_eq!(libc.module_offset, 0x123);
    }

    #[test]
    fn unmapped_ip_does_not_resolve() {
        let map = ProcessModuleMap::parse_maps(MAPS);
        assert!(map.resolve(0x10).is_none());
        assert!(map.resolve(0x55f000001500).is_none());
        assert!(map.resolve(0x7ffffffff000).is_none());
    }

    #[test]
    fn maps_parsing_never_panics_on_arbitrary_lines() {
        for seed in 0..=u8::MAX {
            let line: String = (0..40)
                .map(|index| char::from(seed.wrapping_add(index).max(9)))
                .collect();
            let _ = ProcessModuleMap::parse_maps(&line);
        }
        let _ = ProcessModuleMap::parse_maps("garbage without-dashes xp\n---\n\0\0\0");
    }

    fn synthetic_elf(functions: &[(u64, u64, &str)]) -> Vec<u8> {
        // Minimal little-endian ELF64 with one SHT_SYMTAB and its string
        // table. Layout: [ehdr(64)] [symtab] [strtab] [shdr*3].
        let mut strtab = vec![0u8];
        let mut name_offsets = Vec::new();
        for (_, _, name) in functions {
            name_offsets.push(strtab.len() as u32);
            strtab.extend_from_slice(name.as_bytes());
            strtab.push(0);
        }

        let mut symtab = vec![0u8; 24]; // index 0 is the null symbol
        for ((value, size, _), name_offset) in functions.iter().zip(&name_offsets) {
            let mut entry = Vec::new();
            entry.extend_from_slice(&name_offset.to_le_bytes());
            entry.push(STT_FUNC);
            entry.push(0);
            entry.extend_from_slice(&0u16.to_le_bytes());
            entry.extend_from_slice(&value.to_le_bytes());
            entry.extend_from_slice(&size.to_le_bytes());
            symtab.extend_from_slice(&entry);
        }

        let ehdr_size = 64usize;
        let symtab_offset = ehdr_size;
        let strtab_offset = symtab_offset + symtab.len();
        let shdr_offset = strtab_offset + strtab.len();
        let shdr_size = 64usize;

        let mut image = vec![0u8; shdr_offset + shdr_size * 3];
        image[..4].copy_from_slice(&ELF_MAGIC);
        image[4] = ELFCLASS64;
        image[5] = 1; // little endian
        image[40..48].copy_from_slice(&(shdr_offset as u64).to_le_bytes());
        image[58..60].copy_from_slice(&(shdr_size as u16).to_le_bytes());
        image[60..62].copy_from_slice(&3u16.to_le_bytes());
        image[symtab_offset..symtab_offset + symtab.len()].copy_from_slice(&symtab);
        image[strtab_offset..strtab_offset + strtab.len()].copy_from_slice(&strtab);

        // Section 0: null. Section 1: symtab. Section 2: strtab.
        let symtab_shdr = shdr_offset + shdr_size;
        image[symtab_shdr + 4..symtab_shdr + 8].copy_from_slice(&SHT_SYMTAB.to_le_bytes());
        image[symtab_shdr + 24..symtab_shdr + 32]
            .copy_from_slice(&(symtab_offset as u64).to_le_bytes());
        image[symtab_shdr + 32..symtab_shdr + 40]
            .copy_from_slice(&(symtab.len() as u64).to_le_bytes());
        image[symtab_shdr + 40..symtab_shdr + 44].copy_from_slice(&2u32.to_le_bytes());
        image[symtab_shdr + 56..symtab_shdr + 64].copy_from_slice(&24u64.to_le_bytes());

        let strtab_shdr = shdr_offset + shdr_size * 2;
        image[strtab_shdr + 24..strtab_shdr + 32]
            .copy_from_slice(&(strtab_offset as u64).to_le_bytes());
        image[strtab_shdr + 32..strtab_shdr + 40]
            .copy_from_slice(&(strtab.len() as u64).to_le_bytes());

        image
    }

    #[test]
    fn elf_symbol_table_resolves_function_names() {
        let image = synthetic_elf(&[(0x1000, 0x40, "handle_request"), (0x1100, 0x20, "parse")]);
        let table = ElfSymbolTable::parse(&image);
        assert_eq!(table.len(), 2);
        assert_eq!(table.resolve(0x1000), Some("handle_request"));
        assert_eq!(table.resolve(0x1020), Some("handle_request"));
        assert_eq!(table.resolve(0x1100), Some("parse"));
        // Between the end of handle_request (0x1040) and parse there is no
        // covering function.
        assert_eq!(table.resolve(0x1080), None);
    }

    #[test]
    fn elf_parsing_returns_empty_on_garbage() {
        assert!(ElfSymbolTable::parse(&[]).is_empty());
        assert!(ElfSymbolTable::parse(b"not an elf file at all").is_empty());
        for seed in 0..=u8::MAX {
            let bytes: Vec<u8> = (0..128u16)
                .map(|index| seed.wrapping_add(index as u8))
                .collect();
            let _ = ElfSymbolTable::parse(&bytes);
        }
    }
}
