use std::borrow::Cow;

use e_navigator_profiling::demangle::{CppDemangleMode, demangle_cpp_symbol};

const TEMPLATE_FUNCTION: &str = "_ZN3foo3barIiEEvT_";

#[test]
fn alloy_compatible_modes_control_cpp_symbol_detail() {
    assert_eq!(
        demangle_cpp_symbol(TEMPLATE_FUNCTION, CppDemangleMode::None, 256),
        Cow::Borrowed(TEMPLATE_FUNCTION)
    );
    assert_eq!(
        demangle_cpp_symbol(TEMPLATE_FUNCTION, CppDemangleMode::Simplified, 256),
        "foo::bar"
    );
    assert_eq!(
        demangle_cpp_symbol(TEMPLATE_FUNCTION, CppDemangleMode::Templates, 256),
        "foo::bar<int>"
    );
    assert_eq!(
        demangle_cpp_symbol(TEMPLATE_FUNCTION, CppDemangleMode::Full, 256),
        "void foo::bar<int>(int)"
    );
}

#[test]
fn invalid_and_expanding_symbols_fail_closed_to_the_input() {
    let invalid = "ordinary_function";
    assert_eq!(
        demangle_cpp_symbol(invalid, CppDemangleMode::Full, 256),
        Cow::Borrowed(invalid)
    );
    assert_eq!(
        demangle_cpp_symbol(TEMPLATE_FUNCTION, CppDemangleMode::Full, 8),
        Cow::Borrowed(TEMPLATE_FUNCTION)
    );
}

#[test]
fn simplified_mode_removes_nested_templates_without_damaging_operators() {
    assert_eq!(
        demangle_cpp_symbol(
            "_ZN3foo3barISt6vectorIiSaIiEEEEvT_",
            CppDemangleMode::Simplified,
            256,
        ),
        "foo::bar"
    );
    assert_eq!(
        demangle_cpp_symbol("_ZNK3FooIiEclEv", CppDemangleMode::Simplified, 256,),
        "Foo::operator()"
    );
}
