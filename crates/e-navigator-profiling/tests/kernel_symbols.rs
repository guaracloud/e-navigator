use e_navigator_profiling::kernel::{KernelSymbolLimits, KernelSymbolTable};

#[test]
fn resolves_bounded_kernel_and_module_symbols_without_crossing_ranges() {
    let table = KernelSymbolTable::parse(
        "ffffffff81000000 T _stext\n\
         ffffffff81000100 t schedule\n\
         ffffffff81000180 t worker_tick [worker_mod]\n\
         ffffffff81000200 T _etext\n",
        &KernelSymbolLimits {
            max_symbols: 16,
            max_symbol_bytes: 64,
            max_module_bytes: 64,
        },
    );

    let core = table
        .resolve(0xffff_ffff_8100_0118)
        .expect("core symbol resolves inside its range");
    assert_eq!(core.name, "schedule");
    assert_eq!(core.module, None);
    assert_eq!(core.offset, 0x18);

    let module = table
        .resolve(0xffff_ffff_8100_01a0)
        .expect("module symbol resolves inside its range");
    assert_eq!(module.name, "worker_tick");
    assert_eq!(module.module, Some("worker_mod"));
    assert_eq!(module.offset, 0x20);

    assert!(table.resolve(0xffff_ffff_8100_0300).is_none());
}

#[test]
fn rejects_hidden_addresses_and_control_characters() {
    let table = KernelSymbolTable::parse(
        "0000000000000000 T hidden\n\
         0000000000001000 T bad\0name\n\
         0000000000001100 T valid\n\
         0000000000001200 T boundary\n",
        &KernelSymbolLimits::default(),
    );

    assert!(table.resolve(0).is_none());
    assert!(table.resolve(0x1000).is_none());
    assert_eq!(
        table.resolve(0x1110).map(|symbol| symbol.name),
        Some("valid")
    );
}

#[test]
fn enforces_symbol_and_string_limits() {
    let table = KernelSymbolTable::parse(
        "0000000000001000 T first_long_name [module_long_name]\n\
         0000000000001100 T second\n\
         0000000000001200 T third\n",
        &KernelSymbolLimits {
            max_symbols: 2,
            max_symbol_bytes: 5,
            max_module_bytes: 6,
        },
    );

    let first = table.resolve(0x1000).expect("first symbol resolves");
    assert_eq!(first.name, "first");
    assert_eq!(first.module, Some("module"));
    assert!(table.resolve(0x1200).is_none());
}
