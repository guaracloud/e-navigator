//! Bounded symbolization for addresses captured from the running kernel.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelSymbolLimits {
    pub max_symbols: usize,
    pub max_symbol_bytes: usize,
    pub max_module_bytes: usize,
}

impl Default for KernelSymbolLimits {
    fn default() -> Self {
        Self {
            max_symbols: 262_144,
            max_symbol_bytes: 256,
            max_module_bytes: 256,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KernelSymbol {
    address: u64,
    name: String,
    module: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedKernelSymbol<'a> {
    pub name: &'a str,
    pub module: Option<&'a str>,
    pub offset: u64,
}

/// An immutable, bounded snapshot of non-zero `/proc/kallsyms` entries.
///
/// Addresses hidden by `kptr_restrict` are represented as zero in procfs and
/// are deliberately omitted. Resolution also requires a known upper range,
/// except for an exact match on the final symbol, so an arbitrary address is
/// never attributed to the last visible kernel symbol.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KernelSymbolTable {
    symbols: Vec<KernelSymbol>,
}

impl KernelSymbolTable {
    pub fn parse(contents: &str, limits: &KernelSymbolLimits) -> Self {
        if limits.max_symbols == 0 || limits.max_symbol_bytes == 0 {
            return Self::default();
        }

        let mut symbols = std::collections::BTreeMap::new();
        for line in contents.lines() {
            if symbols.len() >= limits.max_symbols {
                break;
            }
            let mut fields = line.split_whitespace();
            let Some(address) = fields
                .next()
                .and_then(|value| u64::from_str_radix(value, 16).ok())
            else {
                continue;
            };
            if address == 0 || fields.next().is_none() {
                continue;
            }
            let Some(name) = fields.next() else {
                continue;
            };
            if name.chars().any(char::is_control) {
                continue;
            }
            let name = truncate_utf8(name, limits.max_symbol_bytes);
            if name.is_empty() {
                continue;
            }
            let module = fields.next().and_then(|value| {
                value
                    .strip_prefix('[')
                    .and_then(|value| value.strip_suffix(']'))
                    .filter(|value| {
                        !value.is_empty()
                            && limits.max_module_bytes > 0
                            && !value.chars().any(char::is_control)
                    })
                    .map(|value| truncate_utf8(value, limits.max_module_bytes))
                    .filter(|value| !value.is_empty())
            });
            symbols.entry(address).or_insert_with(|| KernelSymbol {
                address,
                name,
                module,
            });
        }

        Self {
            symbols: symbols.into_values().collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    pub fn resolve(&self, address: u64) -> Option<ResolvedKernelSymbol<'_>> {
        let index = self
            .symbols
            .partition_point(|symbol| symbol.address <= address)
            .checked_sub(1)?;
        let symbol = self.symbols.get(index)?;
        let inside_known_range = self
            .symbols
            .get(index.saturating_add(1))
            .is_some_and(|next| address < next.address);
        if address != symbol.address && !inside_known_range {
            return None;
        }
        Some(ResolvedKernelSymbol {
            name: &symbol.name,
            module: symbol.module.as_deref(),
            offset: address.saturating_sub(symbol.address),
        })
    }
}

fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes.min(value.len());
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}
