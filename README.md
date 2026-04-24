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

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

## Support This Project

If you find this project useful, consider buying me a coffee! Your support helps me keep building and sharing open-source tools.

[![Donate via PayPal](https://img.shields.io/badge/Donate-PayPal-blue.svg?logo=paypal)](https://www.paypal.me/baal_hosting)

**PayPal:** [baal_hosting@live.com](https://paypal.me/baal_hosting)

Every donation, no matter how small, is greatly appreciated and motivates continued development. Thank you!
