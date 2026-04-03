# Changelog

## 0.1.0 (2026-04-03)

- Initial release
- ELF64 header parsing and validation
- Program header (LOAD, DYNAMIC, INTERP) processing
- Section header parsing
- PIE/ASLR relocation support (R_X86_64_RELATIVE, R_X86_64_JUMP_SLOT, R_X86_64_GLOB_DAT)
- Memory-mapped loading with page-aligned segments
