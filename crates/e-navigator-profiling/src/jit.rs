//! Bounded parser and resolver for Linux `perf-<pid>.map` JIT symbol maps.
//!
//! Node/V8 and JVM tooling can publish generated-code names through this
//! format. The collector treats the file as untrusted runtime input: malformed
//! rows are skipped, names and entry counts are capped, and overlapping ranges
//! resolve to the entry with the greatest start address.

const MAX_JIT_SYMBOLS: usize = 200_000;
const MAX_JIT_SYMBOL_NAME_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
struct JitSymbol {
    start: u64,
    end: u64,
    name: String,
}

/// A bounded, address-ordered JIT symbol map.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct JitSymbolMap {
    symbols: Vec<JitSymbol>,
    prefix_max_end: Vec<u64>,
}

/// One resolved generated-code location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedJitSymbol<'a> {
    pub name: &'a str,
    pub offset: u64,
}

impl JitSymbolMap {
    /// Parses rows of `<hex-address> <hex-size> <symbol name>`.
    ///
    /// Invalid, zero-sized, overflowing, control-character-containing, and
    /// overlong rows are ignored rather than partially trusted.
    pub fn parse(contents: &str) -> Self {
        let mut symbols = Vec::new();
        for line in contents.lines() {
            if symbols.len() >= MAX_JIT_SYMBOLS {
                break;
            }
            let Some(symbol) = parse_line(line) else {
                continue;
            };
            symbols.push(symbol);
        }
        symbols.sort_by_key(|symbol| symbol.start);
        let mut maximum = 0;
        let prefix_max_end = symbols
            .iter()
            .map(|symbol| {
                maximum = maximum.max(symbol.end);
                maximum
            })
            .collect();
        Self {
            symbols,
            prefix_max_end,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Resolves an absolute instruction pointer to a generated-code name.
    pub fn resolve(&self, ip: u64) -> Option<ResolvedJitSymbol<'_>> {
        let upper_bound = self.symbols.partition_point(|symbol| symbol.start <= ip);
        let mut index = upper_bound.checked_sub(1)?;

        // Duplicate starts are valid in append-only perf maps; prefer the last
        // published row. Walk backwards only across overlapping candidates.
        loop {
            let symbol = &self.symbols[index];
            if ip >= symbol.start && ip < symbol.end {
                return Some(ResolvedJitSymbol {
                    name: &symbol.name,
                    offset: ip - symbol.start,
                });
            }
            if index == 0 || self.prefix_max_end[index - 1] <= ip {
                return None;
            }
            index -= 1;
        }
    }
}

fn parse_line(line: &str) -> Option<JitSymbol> {
    let line = line.trim_start();
    let address_end = line.find(char::is_whitespace)?;
    let (address, rest) = line.split_at(address_end);
    let rest = rest.trim_start();
    let size_end = rest.find(char::is_whitespace)?;
    let (size, name) = rest.split_at(size_end);
    let start = parse_hex(address)?;
    let size = parse_hex(size)?;
    let name = name.trim();
    if size == 0
        || name.is_empty()
        || name.len() > MAX_JIT_SYMBOL_NAME_BYTES
        || name.chars().any(char::is_control)
    {
        return None;
    }
    let end = start.checked_add(size)?;
    Some(JitSymbol {
        start,
        end,
        name: name.to_string(),
    })
}

fn parse_hex(value: &str) -> Option<u64> {
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    (!value.is_empty())
        .then(|| u64::from_str_radix(value, 16).ok())
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_resolves_node_and_jvm_perf_map_rows() {
        let map = JitSymbolMap::parse(
            "7f0100001000 30 LazyCompile:*busy /app/server.js:12\n\
             0x7f0100002000 0x40 java::com.example.Worker::run\n",
        );

        assert_eq!(map.len(), 2);
        assert_eq!(
            map.resolve(0x7f0100001010),
            Some(ResolvedJitSymbol {
                name: "LazyCompile:*busy /app/server.js:12",
                offset: 0x10,
            })
        );
        assert_eq!(
            map.resolve(0x7f010000203f),
            Some(ResolvedJitSymbol {
                name: "java::com.example.Worker::run",
                offset: 0x3f,
            })
        );
        assert_eq!(map.resolve(0x7f0100002040), None);
    }

    #[test]
    fn rejects_malformed_unbounded_or_unsafe_rows() {
        let map = JitSymbolMap::parse(&format!(
            "not-hex 20 bad\n1000 0 zero\n2000 20 bad\tname\n3000 20 {}\n4000 20 valid name\n",
            "x".repeat(MAX_JIT_SYMBOL_NAME_BYTES + 1)
        ));

        assert_eq!(map.len(), 1);
        assert_eq!(
            map.resolve(0x4010).map(|symbol| symbol.name),
            Some("valid name")
        );
    }

    #[test]
    fn overlapping_ranges_prefer_greatest_start() {
        let map = JitSymbolMap::parse(
            "1000 1000 outer\n1500 20 expired-middle\n1800 20 expired-latest\n1080 20 inner\n",
        );
        assert_eq!(map.resolve(0x1088).map(|symbol| symbol.name), Some("inner"));
        assert_eq!(map.resolve(0x1900).map(|symbol| symbol.name), Some("outer"));
    }
}
