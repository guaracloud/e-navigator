//! Bounded C++ symbol demangling for profile frames.

use std::borrow::Cow;

use cpp_demangle::{DemangleNodeType, DemangleOptions, DemangleWrite, ParseOptions, Symbol};

const CPP_DEMANGLE_RECURSION_LIMIT: u32 = 64;

/// C++ demangling detail compatible with Grafana Alloy's profile labels.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CppDemangleMode {
    /// Preserve the linker symbol exactly as observed.
    None,
    /// Remove function parameters, return types, and template arguments.
    #[default]
    Simplified,
    /// Keep template arguments while removing function parameters and return types.
    Templates,
    /// Preserve all detail produced by the bounded demangler.
    Full,
}

/// Demangle an Itanium C++ ABI symbol without allowing the rendered name to
/// exceed `max_symbol_bytes`.
///
/// Non-C++ symbols, disabled demangling, parse failures, render failures, and
/// expansions beyond the caller's existing signal bound preserve the input.
pub fn demangle_cpp_symbol(
    symbol: &str,
    mode: CppDemangleMode,
    max_symbol_bytes: usize,
) -> Cow<'_, str> {
    if mode == CppDemangleMode::None || symbol.len() > max_symbol_bytes {
        return Cow::Borrowed(symbol);
    }
    let parse_options = ParseOptions::default().recursion_limit(CPP_DEMANGLE_RECURSION_LIMIT);
    let Ok(parsed) = Symbol::new_with_options(symbol, &parse_options) else {
        return Cow::Borrowed(symbol);
    };
    let options = match mode {
        CppDemangleMode::None => return Cow::Borrowed(symbol),
        CppDemangleMode::Simplified | CppDemangleMode::Templates => {
            DemangleOptions::default().no_params().no_return_type()
        }
        CppDemangleMode::Full => DemangleOptions::default(),
    }
    .recursion_limit(CPP_DEMANGLE_RECURSION_LIMIT);
    let mut rendered =
        BoundedDemangleWriter::new(max_symbol_bytes, mode == CppDemangleMode::Simplified);
    if parsed.structured_demangle(&mut rendered, &options).is_err() {
        return Cow::Borrowed(symbol);
    }
    Cow::Owned(rendered.output)
}

#[derive(Debug)]
struct BoundedDemangleWriter {
    output: String,
    max_bytes: usize,
    hide_templates: bool,
    template_depth: usize,
    nodes: Vec<DemangleNodeType>,
    skip_closing_template_angle: bool,
}

impl BoundedDemangleWriter {
    fn new(max_bytes: usize, hide_templates: bool) -> Self {
        Self {
            output: String::with_capacity(max_bytes.min(256)),
            max_bytes,
            hide_templates,
            template_depth: 0,
            nodes: Vec::new(),
            skip_closing_template_angle: false,
        }
    }
}

impl DemangleWrite for BoundedDemangleWriter {
    fn push_demangle_node(&mut self, node: DemangleNodeType) {
        if self.hide_templates && node == DemangleNodeType::TemplateArgs {
            if self.template_depth == 0 && self.output.ends_with('<') {
                self.output.pop();
            }
            self.template_depth = self.template_depth.saturating_add(1);
        }
        self.nodes.push(node);
    }

    fn write_string(&mut self, value: &str) -> std::fmt::Result {
        if self.template_depth > 0 {
            return Ok(());
        }
        let value = if self.skip_closing_template_angle {
            self.skip_closing_template_angle = false;
            value.strip_prefix('>').unwrap_or(value)
        } else {
            value
        };
        if self.output.len().saturating_add(value.len()) > self.max_bytes {
            return Err(std::fmt::Error);
        }
        self.output.push_str(value);
        Ok(())
    }

    fn pop_demangle_node(&mut self) {
        let Some(node) = self.nodes.pop() else {
            return;
        };
        if self.hide_templates && node == DemangleNodeType::TemplateArgs {
            self.template_depth = self.template_depth.saturating_sub(1);
            if self.template_depth == 0 {
                self.skip_closing_template_angle = true;
            }
        }
    }
}
