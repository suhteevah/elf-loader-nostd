# elf-loader-nostd

`no_std` ELF64 binary loader with PIE/ASLR support in Rust.

## Features

- ELF64 header parsing and validation (magic, class, endianness, machine type)
- Program header processing: PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_PHDR
- Section header parsing with string table lookup
- PIE binary relocation (R_X86_64_RELATIVE, R_X86_64_JUMP_SLOT, R_X86_64_GLOB_DAT)
- Memory-mapped loading with page-aligned segments
- Segment permission mapping (read/write/execute)

## License

Licensed under either of Apache License 2.0 or MIT License at your option.
