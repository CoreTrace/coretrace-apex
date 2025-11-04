# coretrace-apex



**APEX** - Analysis & Parsing of Executables and eXports



Binary Structure Analysis & Symbol Tracing Tool for PE and ELF FormatsBinary Analysis & Symbol Tracing Tool for PE and ELF FormatsMulti-platform Analysis, Tracing & Tooling for Hooking, Instrumentation, Addresses, and Symbols



---



## OverviewTagline: Cross-platform binary structure analysis with function and variable discovery.Tagline: Cross-OS binary function/variable discovery and runtime tracing.



**coretrace-apex** is a lightweight C tool designed to help reverse engineers, security researchers, and systems programmers analyze binary structures across Windows (PE) and Linux (ELF) platforms. It detects binary formats, extracts sections, enumerates functions and variables from symbol tables, and optionally generates graph visualizations of the binary's internal structure.



The project name reflects its core purpose: tracing the core structures of compiled binaries to understand their organization and exported symbols. **APEX** stands for **Analysis & Parsing of Executables and eXports**.------



## Key Features



- **Cross-platform binary analysis**: Automatically detect PE (Windows) or ELF (Linux/Unix) format## Overview## Overview

- **Section enumeration**: List all sections with virtual addresses, sizes, and characteristics

- **Symbol table parsing**: Extract functions and variables from:

  - ELF: `.symtab` and `.dynsym` symbol tables

  - PE: Export tables and COFF symbol tables**coretrace-analyzer** is a lightweight C tool designed to help reverse engineers, security researchers, and systems programmers analyze binary structures across Windows (PE) and Linux (ELF) platforms. It detects binary formats, extracts sections, enumerates functions and variables from symbol tables, and optionally generates graph visualizations of the binary's internal structure.MATTHIAS is a lightweight C tool designed to help reverse engineers, security researchers, and systems programmers analyze binaries across Windows and Linux. It detects binary formats (PE vs ELF), extracts function addresses and symbols where available, and supports tracing and hooking workflows for runtime inspection and variable discovery.

- **Graph visualization**: Generate `.dot` files (Graphviz format) showing binary structure with `--report` flag

- **Native implementation**: Pure C with no external tool dependencies (readelf, objdump, etc.)

- **Architecture detection**: Identify 32-bit vs 64-bit binaries

- **Modular design**: Easy to extend with additional parsers or output formatsThe project name reflects its core purpose: tracing the core structures of compiled binaries to understand their organization and exported symbols.The project name is an acronym that reflects its goals: Multi-platform Analysis, Tracing & Tooling for Hooking, Instrumentation, Addresses, and Symbols.



## Why coretrace-apex?



The tool emphasizes detailed core-level analysis of binary structures, making it ideal for understanding how executables are organized, what functions they export, and how their data is laid out in memory. The name "APEX" signifies peak performance in binary analysis - reaching the apex of executable understanding.## Key Features## Key features



## Usage



### Basic Commands- **Cross-platform binary analysis**: Automatically detect PE (Windows) or ELF (Linux/Unix) format- Cross-platform static analysis: detect whether a binary is PE (Windows) or ELF (Linux) and report basic metadata.



```bash- **Section enumeration**: List all sections with virtual addresses, sizes, and characteristics- Function/address discovery: enumerate exports, symbol table entries, and obvious function start addresses.

# View available commands

./coretrace-apex help- **Symbol table parsing**: Extract functions and variables from:- Runtime tracing & hooking primitives: foundations to attach or instrument processes for dynamic discovery of functions and variables (dependent on platform-specific APIs and permissions).



# Scan a binary (console output)  - ELF: `.symtab` and `.dynsym` symbol tables- JSON and human-friendly CLI output for integration with other tools and pipelines.

./coretrace-apex scan ./path/to/binary

  - PE: Export tables and COFF symbol tables- Modular design to add new parsers, architectures, or instrumentation backends.

# Scan with graph report generation

./coretrace-apex scan ./path/to/binary --report- **Graph visualization**: Generate `.dot` files (Graphviz format) showing binary structure with `--report` flag

```

- **Native implementation**: Pure C with no external tool dependencies (readelf, objdump, etc.)## Why this fits the project goals

### Available Commands

- **Architecture detection**: Identify 32-bit vs 64-bit binaries

- `scan` - Analyze binary structure, sections, and symbols

- `functions` - List all functions (reserved for future use)- **Modular design**: Easy to extend with additional parsers or output formatsMATTHIAS emphasizes cross-OS support (Windows and Linux), focuses on extracting function addresses and symbols, and includes tooling foundations for hooking and instrumentation. The name communicates both static analysis and dynamic tracing capabilities, which matches the intended scope.

- `variables` - List all variables (reserved for future use)

- `help` - Show available commands and flags



### Optional Flags## Why coretrace-analyzer?## Minimal contract



- `--report` - Generate a `.dot` graph file with visual representation of binary structure



## Output ExamplesThe tool emphasizes detailed core-level analysis of binary structures, making it ideal for understanding how executables are organized, what functions they export, and how their data is laid out in memory. The name "coretrace" reflects both the core (structure) analysis and the ability to trace symbols through tables and sections.- Inputs: path(s) to binary files (PE/ELF). Optionally, a PID or process handle for live analysis.



### Console Output (ELF64)- Outputs: identified format (PE or ELF), list of discovered functions with addresses, optional variables or inferred symbols, printed as JSON or a CLI table.



```txt## Usage- Error modes: unsupported file format, stripped/obfuscated binaries (limited info), insufficient permissions for runtime attachments.

=== ELF64 Header ===

Entry point: 0x0000000000001260

Section headers: 31 (offset: 0x8c38)

### Basic Commands## Dependencies (suggested)

=== Sections ===

Name                 Type         Address            Size      

.text                0x00000001   0x0000000000001260   19777

.data                0x00000001   0x0000000000008000   72```bashThe core README is intentionally implementation-agnostic. When scaffolding the C project, consider these libraries:

.rodata              0x00000001   0x0000000000006000   3288

# View available commands

=== Symbol Table: .symtab ===

Name                                     Type         Address            Size./coretrace-analyzer help- ELF parsing: libelf or elfutils

main                                     FUNC         0x0000000000001350   245

parse_elf                                FUNC         0x0000000000003fd3   108- PE parsing: pe-parse, libpe, or manual parsing using Windows headers

```

# Scan a binary (console output)- Disassembly / analysis: Capstone (for identifying function starts and heuristics)

### Graph Output (.dot files)

./coretrace-analyzer scan ./path/to/binary- Optional: libbfd (from binutils) for advanced symbol handling

When using `--report`, the tool generates Graphviz `.dot` files showing:

- All sections with addresses and sizes

- Symbol tables with function/variable names and addresses

- Relationships between sections and symbol tables# Scan with graph report generationPlatform notes: runtime tracing and hooking will require platform-specific APIs (ptrace on Linux, Windows Debugging APIs / Detours-like hooking on Windows) and appropriate privileges.



Visualize with:./coretrace-analyzer scan ./path/to/binary --report

```bash

dot -Tpng binary_elf64.dot -o binary_structure.png```## Usage (example CLI)

dot -Tsvg binary_pe.dot -o binary_structure.svg

```



## Building### Available CommandsBasic static scan:



```bash

make          # Build the project

make clean    # Remove object files- `scan` - Analyze binary structure, sections, and symbols```sh

make fclean   # Remove all build artifacts

make re       # Rebuild from scratch- `functions` - List all functions (reserved for future use)matthias scan ./binaries/sample_binary -o sample_report.json

```

- `variables` - List all variables (reserved for future use)```

## Dependencies

- `help` - Show available commands and flags

- **Standard C library** (libc)

- **ELF parsing**: Uses `<elf.h>` from standard headersQuick output (stdout):

- **PE parsing**: Custom implementation with packed structures

- **No external tools required** for parsing (unlike tools that shell out to readelf/objdump)### Optional Flags



Optional for visualization:```txt

- **Graphviz** (`dot` command) - to render `.dot` files to images

- `--report` - Generate a `.dot` graph file with visual representation of binary structureFormat: ELF (x86_64)

## Supported Formats

Functions:

| Format | Architectures | Symbol Sources |

|--------|---------------|----------------|## Output Examples- 0x400560  main

| ELF    | 32-bit, 64-bit | .symtab, .dynsym |

| PE     | PE32, PE32+ (64-bit) | Export table, COFF symbols |- 0x4004d0  helper_func



## Edge Cases & Limitations### Console Output (ELF64)```



- **Stripped binaries**: Symbol names may be unavailable; only addresses are shown

- **Packed/obfuscated binaries**: May require unpacking before analysis

- **Large symbol tables**: Graph generation limits symbols to first 50 entries per table to keep .dot files manageable```txtJSON output:

- **Cross-compilation**: Reads binaries regardless of host platform (can analyze Windows PE on Linux and vice versa)

=== ELF64 Header ===

## Project Structure

Entry point: 0x0000000000001260```json

```

coretrace-apex/Section headers: 31 (offset: 0x8c38){

├── includes/

│   └── binary.h          # Main header with structures and function declarations  "file": "sample_binary",

├── src/

│   ├── main.c           # Entry point=== Sections ===  "format": "ELF",

│   ├── file_manager.c   # Argument parsing and file type detection

│   ├── binary_handler.c # Dispatcher to appropriate parserName                 Type         Address            Size        "arch": "x86_64",

│   ├── elf_parser.c     # ELF32/64 parsing with .dot generation

│   └── pe_parser.c      # PE32/PE32+ parsing with .dot generation.text                0x00000001   0x0000000000001260   19777  "functions": [

├── Makefile             # Build configuration

└── README.md           # This file.data                0x00000001   0x0000000000008000   72    { "name": "main", "addr": "0x400560" },

```

.rodata              0x00000001   0x0000000000006000   3288    { "name": "helper_func", "addr": "0x4004d0" }

## Contributing

  ]

Contributions are welcome! Areas for enhancement:

- Additional binary formats (Mach-O for macOS)=== Symbol Table: .symtab ===}

- More detailed symbol type classification

- JSON output format optionName                                     Type         Address            Size```

- Interactive symbol search/filtering

- Disassembly integrationmain                                     FUNC         0x0000000000001350   245



Please open issues for feature requests and submit pull requests with test cases.parse_elf                                FUNC         0x0000000000003fd3   108## Edge cases & limitations



## License```



GPLV3- Stripped binaries: function names may be unavailable; heuristics or disassembly will be required to identify function starts.


### Graph Output (.dot files)- Packed/obfuscated binaries: static analysis may be insufficient — runtime tracing or unpacking is required.

- Multi-architecture support: cross-arch binaries (or unknown endianness) require explicit handling.

When using `--report`, the tool generates Graphviz `.dot` files showing:- Permissions: attaching to processes or reading other process memory may require root/Administrator privileges.

- All sections with addresses and sizes

- Symbol tables with function/variable names and addresses## Contributing

- Relationships between sections and symbol tables

Contributions are welcome. Please open issues for feature requests and submit pull requests for bug fixes and enhancements. Provide reproducible test cases for new parsers or instrumentation backends.

Visualize with:

```bash## License

dot -Tpng binary_elf64.dot -o binary_structure.png

dot -Tsvg binary_pe.dot -o binary_structure.svgGPLV3

```

## Building

```bash
make          # Build the project
make clean    # Remove object files
make fclean   # Remove all build artifacts
make re       # Rebuild from scratch
```

## Dependencies

- **Standard C library** (libc)
- **ELF parsing**: Uses `<elf.h>` from standard headers
- **PE parsing**: Custom implementation with packed structures
- **No external tools required** for parsing (unlike tools that shell out to readelf/objdump)

Optional for visualization:
- **Graphviz** (`dot` command) - to render `.dot` files to images

## Supported Formats

| Format | Architectures | Symbol Sources |
|--------|---------------|----------------|
| ELF    | 32-bit, 64-bit | .symtab, .dynsym |
| PE     | PE32, PE32+ (64-bit) | Export table, COFF symbols |

## Edge Cases & Limitations

- **Stripped binaries**: Symbol names may be unavailable; only addresses are shown
- **Packed/obfuscated binaries**: May require unpacking before analysis
- **Large symbol tables**: Graph generation limits symbols to first 50 entries per table to keep .dot files manageable
- **Cross-compilation**: Reads binaries regardless of host platform (can analyze Windows PE on Linux and vice versa)

## Project Structure

```
coretrace-analyzer/
├── includes/
│   └── binary.h          # Main header with structures and function declarations
├── src/
│   ├── main.c           # Entry point
│   ├── file_manager.c   # Argument parsing and file type detection
│   ├── binary_handler.c # Dispatcher to appropriate parser
│   ├── elf_parser.c     # ELF32/64 parsing with .dot generation
│   └── pe_parser.c      # PE32/PE32+ parsing with .dot generation
├── Makefile             # Build configuration
└── README.md           # This file
```

## Contributing

Contributions are welcome! Areas for enhancement:
- Additional binary formats (Mach-O for macOS)
- More detailed symbol type classification
- JSON output format option
- Interactive symbol search/filtering
- Disassembly integration

Please open issues for feature requests and submit pull requests with test cases.

## License

GPL-3.0 license