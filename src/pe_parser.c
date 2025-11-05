#include "../includes/binary.h"

/* PE structures */
#pragma pack(push, 1)
typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

typedef struct {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
} IMAGE_OPTIONAL_HEADER_COMMON;

typedef struct {
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
} IMAGE_OPTIONAL_HEADER32_REST;

typedef struct {
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
} IMAGE_OPTIONAL_HEADER64_REST;

typedef struct {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} IMAGE_DATA_DIRECTORY;

typedef struct {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;
    uint32_t AddressOfNames;
    uint32_t AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY;

typedef struct {
    union {
        char ShortName[8];
        struct {
            uint32_t Zeroes;
            uint32_t Offset;
        } Name;
    } N;
    uint32_t Value;
    int16_t  SectionNumber;
    uint16_t Type;
    uint8_t  StorageClass;
    uint8_t  NumberOfAuxSymbols;
} IMAGE_SYMBOL;

#pragma pack(pop)

#define IMAGE_FILE_MACHINE_I386  0x014c
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b

/* RVA to file offset conversion */
static uint32_t rva_to_offset(IMAGE_SECTION_HEADER *sections, int num_sections, uint32_t rva)
{
    for (int i = 0; i < num_sections; i++) {
        if (rva >= sections[i].VirtualAddress && 
            rva < sections[i].VirtualAddress + sections[i].VirtualSize) {
            return rva - sections[i].VirtualAddress + sections[i].PointerToRawData;
        }
    }
    return 0;
}

void parse_pe(const char *filepath, int generate_dot)
{
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        fprintf(stderr, "Failed to open file: %s\n", filepath);
        return;
    }

    /* Read DOS header to get PE offset */
    uint8_t dos_header[64];
    fread(dos_header, 1, 64, file);
    uint32_t pe_offset = *(uint32_t*)(dos_header + 0x3C);

    /* Read PE signature */
    fseek(file, pe_offset, SEEK_SET);
    uint32_t pe_sig;
    fread(&pe_sig, 4, 1, file);
    
    if (pe_sig != 0x00004550) { // "PE\0\0"
        fprintf(stderr, "Invalid PE signature\n");
        fclose(file);
        return;
    }

    /* Read COFF header */
    IMAGE_FILE_HEADER coff_header;
    fread(&coff_header, sizeof(coff_header), 1, file);

    printf("\n=== PE Header ===\n");
    printf("Machine: 0x%04x (%s)\n", coff_header.Machine,
           coff_header.Machine == IMAGE_FILE_MACHINE_I386 ? "x86" :
           coff_header.Machine == IMAGE_FILE_MACHINE_AMD64 ? "x64" : "Unknown");
    printf("Number of sections: %u\n", coff_header.NumberOfSections);
    printf("Number of symbols: %u\n", coff_header.NumberOfSymbols);

    /* Read optional header (common part) */
    IMAGE_OPTIONAL_HEADER_COMMON opt_common;
    fread(&opt_common, sizeof(opt_common), 1, file);

    int is_pe32_plus = (opt_common.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    
    printf("Optional header magic: 0x%04x (%s)\n", opt_common.Magic,
           is_pe32_plus ? "PE32+" : "PE32");
    printf("Entry point: 0x%08x\n", opt_common.AddressOfEntryPoint);
    printf("Base of code: 0x%08x\n", opt_common.BaseOfCode);

    /* Read rest of optional header and data directories */
    uint32_t num_data_dirs = 0;
    uint64_t image_base = 0;
    
    if (is_pe32_plus) {
        IMAGE_OPTIONAL_HEADER64_REST opt64_rest;
        fread(&opt64_rest, sizeof(opt64_rest), 1, file);
        num_data_dirs = opt64_rest.NumberOfRvaAndSizes;
        image_base = opt64_rest.ImageBase;
    } else {
        IMAGE_OPTIONAL_HEADER32_REST opt32_rest;
        fread(&opt32_rest, sizeof(opt32_rest), 1, file);
        num_data_dirs = opt32_rest.NumberOfRvaAndSizes;
        image_base = opt32_rest.ImageBase;
    }

    printf("Image base: 0x%lx\n", image_base);

    /* Read data directories */
    IMAGE_DATA_DIRECTORY *data_dirs = malloc(sizeof(IMAGE_DATA_DIRECTORY) * num_data_dirs);
    if (data_dirs && num_data_dirs > 0) {
        fread(data_dirs, sizeof(IMAGE_DATA_DIRECTORY), num_data_dirs, file);
    }

    /* Read section headers */
    IMAGE_SECTION_HEADER *sections = malloc(sizeof(IMAGE_SECTION_HEADER) * coff_header.NumberOfSections);
    if (!sections) {
        fprintf(stderr, "Memory allocation failed\n");
        free(data_dirs);
        fclose(file);
        return;
    }

    fread(sections, sizeof(IMAGE_SECTION_HEADER), coff_header.NumberOfSections, file);

    printf("\n=== Sections ===\n");
    printf("%-10s %-12s %-12s %-10s %-10s\n", "Name", "VirtAddr", "VirtSize", "RawSize", "Characteristics");
    printf("%-10s %-12s %-12s %-10s %-10s\n", "----", "--------", "--------", "-------", "---------------");

    for (int i = 0; i < coff_header.NumberOfSections; i++) {
        char name[9] = {0};
        memcpy(name, sections[i].Name, 8);
        printf("%-10s 0x%08x   0x%08x   %-10u 0x%08x\n",
               name, sections[i].VirtualAddress, sections[i].VirtualSize,
               sections[i].SizeOfRawData, sections[i].Characteristics);
    }

    /* Parse export table if present */
    if (data_dirs && num_data_dirs > 0 && data_dirs[0].VirtualAddress != 0) {
        uint32_t export_offset = rva_to_offset(sections, coff_header.NumberOfSections, data_dirs[0].VirtualAddress);
        if (export_offset > 0) {
            fseek(file, export_offset, SEEK_SET);
            IMAGE_EXPORT_DIRECTORY export_dir;
            if (fread(&export_dir, sizeof(export_dir), 1, file) == 1) {
                printf("\n=== Exported Functions ===\n");
                printf("Number of functions: %u\n", export_dir.NumberOfFunctions);
                printf("Number of names: %u\n", export_dir.NumberOfNames);

                if (export_dir.NumberOfNames > 0 && export_dir.NumberOfNames < 10000) {
                    /* Read function addresses */
                    uint32_t *func_addrs = malloc(sizeof(uint32_t) * export_dir.NumberOfFunctions);
                    uint32_t func_offset = rva_to_offset(sections, coff_header.NumberOfSections, export_dir.AddressOfFunctions);
                    if (func_offset && func_addrs) {
                        fseek(file, func_offset, SEEK_SET);
                        fread(func_addrs, sizeof(uint32_t), export_dir.NumberOfFunctions, file);
                    }

                    /* Read name addresses */
                    uint32_t *name_addrs = malloc(sizeof(uint32_t) * export_dir.NumberOfNames);
                    uint32_t name_offset = rva_to_offset(sections, coff_header.NumberOfSections, export_dir.AddressOfNames);
                    if (name_offset && name_addrs) {
                        fseek(file, name_offset, SEEK_SET);
                        fread(name_addrs, sizeof(uint32_t), export_dir.NumberOfNames, file);
                    }

                    /* Read ordinals */
                    uint16_t *ordinals = malloc(sizeof(uint16_t) * export_dir.NumberOfNames);
                    uint32_t ord_offset = rva_to_offset(sections, coff_header.NumberOfSections, export_dir.AddressOfNameOrdinals);
                    if (ord_offset && ordinals) {
                        fseek(file, ord_offset, SEEK_SET);
                        fread(ordinals, sizeof(uint16_t), export_dir.NumberOfNames, file);
                    }

                    printf("\n%-40s %-12s\n", "Name", "Address");
                    printf("%-40s %-12s\n", "----", "-------");

                    for (uint32_t i = 0; i < export_dir.NumberOfNames; i++) {
                        if (name_addrs && ordinals && func_addrs) {
                            uint32_t name_rva_offset = rva_to_offset(sections, coff_header.NumberOfSections, name_addrs[i]);
                            if (name_rva_offset > 0) {
                                char func_name[256] = {0};
                                fseek(file, name_rva_offset, SEEK_SET);
                                fgets(func_name, sizeof(func_name), file);
                                
                                uint16_t ord = ordinals[i];
                                uint32_t func_rva = (ord < export_dir.NumberOfFunctions) ? func_addrs[ord] : 0;
                                
                                printf("%-40s 0x%08x\n", func_name, func_rva);
                            }
                        }
                    }

                    free(func_addrs);
                    free(name_addrs);
                    free(ordinals);
                }
            }
        }
    }

    /* Parse COFF symbol table if present */
    if (coff_header.PointerToSymbolTable > 0 && coff_header.NumberOfSymbols > 0) {
        printf("\n=== COFF Symbol Table ===\n");
        
        fseek(file, coff_header.PointerToSymbolTable, SEEK_SET);
        IMAGE_SYMBOL *symbols = malloc(sizeof(IMAGE_SYMBOL) * coff_header.NumberOfSymbols);
        if (!symbols) {
            fprintf(stderr, "Failed to allocate memory for symbols\n");
        } else {
            fread(symbols, sizeof(IMAGE_SYMBOL), coff_header.NumberOfSymbols, file);

            /* Read string table (immediately after symbol table) */
            uint32_t string_table_offset = coff_header.PointerToSymbolTable + 
                                          (sizeof(IMAGE_SYMBOL) * coff_header.NumberOfSymbols);
            fseek(file, string_table_offset, SEEK_SET);
            uint32_t string_table_size;
            fread(&string_table_size, 4, 1, file);
            
            char *string_table = NULL;
            if (string_table_size > 4 && string_table_size < 1000000) {
                string_table = malloc(string_table_size);
                if (string_table) {
                    fseek(file, string_table_offset, SEEK_SET);
                    fread(string_table, 1, string_table_size, file);
                }
            }

            printf("%-40s %-12s %-10s %-10s\n", "Name", "Section", "Value", "Storage");
            printf("%-40s %-12s %-10s %-10s\n", "----", "-------", "-----", "-------");

            for (uint32_t i = 0; i < coff_header.NumberOfSymbols; i++) {
                char name[256] = {0};
                
                if (symbols[i].N.Name.Zeroes == 0 && string_table) {
                    /* Long name in string table */
                    uint32_t offset = symbols[i].N.Name.Offset;
                    if (offset < string_table_size) {
                        strncpy(name, string_table + offset, sizeof(name) - 1);
                    }
                } else {
                    /* Short name */
                    memcpy(name, symbols[i].N.ShortName, 8);
                }

                if (name[0] != '\0' && symbols[i].StorageClass == 2) { // External symbol
                    printf("%-40s %-12d 0x%08x   %u\n",
                           name, symbols[i].SectionNumber, symbols[i].Value, symbols[i].StorageClass);
                }

                /* Skip auxiliary symbols */
                i += symbols[i].NumberOfAuxSymbols;
            }

            free(string_table);
            free(symbols);
        }
    }

    /* Generate .dot file if requested */
    if (generate_dot) {
        char dotfile[512];
        snprintf(dotfile, sizeof(dotfile), "%s_pe.dot", filepath);
        FILE *dot = fopen(dotfile, "w");
        if (dot) {
            fprintf(dot, "digraph PE {\n");
            fprintf(dot, "  rankdir=LR;\n");
            fprintf(dot, "  node [shape=record];\n\n");
            
            /* Sections node */
            fprintf(dot, "  sections [label=\"{PE Sections");
            for (int i = 0; i < coff_header.NumberOfSections; i++) {
                char name[9] = {0};
                memcpy(name, sections[i].Name, 8);
                
                /* Escape special characters for DOT record labels */
                fprintf(dot, "|{");
                for (int j = 0; name[j] != '\0'; j++) {
                    char c = name[j];
                    if (c == '|' || c == '{' || c == '}' || c == '<' || c == '>' || c == '"' || c == '\\') {
                        fprintf(dot, "\\%c", c);
                    } else if (c == ' ') {
                        fprintf(dot, "\\ "); // Escape spaces
                    } else {
                        fprintf(dot, "%c", c);
                    }
                }
                fprintf(dot, "|0x%08x|%u}", sections[i].VirtualAddress, sections[i].VirtualSize);
            }
            fprintf(dot, "}\"];\n\n");
            
            /* Export table */
            if (data_dirs && num_data_dirs > 0 && data_dirs[0].VirtualAddress != 0) {
                uint32_t export_offset = rva_to_offset(sections, coff_header.NumberOfSections, data_dirs[0].VirtualAddress);
                if (export_offset > 0) {
                    fseek(file, export_offset, SEEK_SET);
                    IMAGE_EXPORT_DIRECTORY export_dir;
                    if (fread(&export_dir, sizeof(export_dir), 1, file) == 1 && export_dir.NumberOfNames > 0 && export_dir.NumberOfNames < 1000) {
                        fprintf(dot, "  exports [label=\"{Exports");
                        
                        uint32_t *func_addrs = malloc(sizeof(uint32_t) * export_dir.NumberOfFunctions);
                        uint32_t *name_addrs = malloc(sizeof(uint32_t) * export_dir.NumberOfNames);
                        uint16_t *ordinals = malloc(sizeof(uint16_t) * export_dir.NumberOfNames);
                        
                        if (func_addrs && name_addrs && ordinals) {
                            uint32_t func_offset = rva_to_offset(sections, coff_header.NumberOfSections, export_dir.AddressOfFunctions);
                            uint32_t name_offset = rva_to_offset(sections, coff_header.NumberOfSections, export_dir.AddressOfNames);
                            uint32_t ord_offset = rva_to_offset(sections, coff_header.NumberOfSections, export_dir.AddressOfNameOrdinals);
                            
                            if (func_offset && name_offset && ord_offset) {
                                fseek(file, func_offset, SEEK_SET);
                                fread(func_addrs, sizeof(uint32_t), export_dir.NumberOfFunctions, file);
                                fseek(file, name_offset, SEEK_SET);
                                fread(name_addrs, sizeof(uint32_t), export_dir.NumberOfNames, file);
                                fseek(file, ord_offset, SEEK_SET);
                                fread(ordinals, sizeof(uint16_t), export_dir.NumberOfNames, file);
                                
                                for (uint32_t i = 0; i < export_dir.NumberOfNames && i < 50; i++) {
                                    uint32_t name_rva_offset = rva_to_offset(sections, coff_header.NumberOfSections, name_addrs[i]);
                                    if (name_rva_offset > 0) {
                                        char func_name[128] = {0};
                                        fseek(file, name_rva_offset, SEEK_SET);
                                        fgets(func_name, sizeof(func_name), file);
                                        // Remove newlines
                                        for (int j = 0; func_name[j]; j++) {
                                            if (func_name[j] == '\n' || func_name[j] == '\r') func_name[j] = '\0';
                                        }
                                        uint16_t ord = ordinals[i];
                                        uint32_t func_rva = (ord < export_dir.NumberOfFunctions) ? func_addrs[ord] : 0;
                                        
                                        /* Escape special characters in function names */
                                        fprintf(dot, "|{");
                                        for (int j = 0; func_name[j] != '\0'; j++) {
                                            char c = func_name[j];
                                            if (c == '|' || c == '{' || c == '}' || c == '<' || c == '>' || c == '"' || c == '\\') {
                                                fprintf(dot, "\\%c", c);
                                            } else if (c == ' ') {
                                                fprintf(dot, "\\ ");
                                            } else {
                                                fprintf(dot, "%c", c);
                                            }
                                        }
                                        fprintf(dot, "|0x%08x}", func_rva);
                                    }
                                }
                            }
                        }
                        
                        fprintf(dot, "}\"];\n");
                        fprintf(dot, "  sections -> exports;\n");
                        
                        free(func_addrs);
                        free(name_addrs);
                        free(ordinals);
                    }
                }
            }
            
            /* COFF symbol table */
            if (coff_header.PointerToSymbolTable > 0 && coff_header.NumberOfSymbols > 0) {
                fprintf(dot, "  symbols [label=\"{COFF Symbols");
                
                fseek(file, coff_header.PointerToSymbolTable, SEEK_SET);
                IMAGE_SYMBOL *symbols = malloc(sizeof(IMAGE_SYMBOL) * coff_header.NumberOfSymbols);
                if (symbols) {
                    fread(symbols, sizeof(IMAGE_SYMBOL), coff_header.NumberOfSymbols, file);
                    
                    uint32_t string_table_offset = coff_header.PointerToSymbolTable + 
                                                  (sizeof(IMAGE_SYMBOL) * coff_header.NumberOfSymbols);
                    fseek(file, string_table_offset, SEEK_SET);
                    uint32_t string_table_size;
                    fread(&string_table_size, 4, 1, file);
                    
                    char *string_table = NULL;
                    if (string_table_size > 4 && string_table_size < 1000000) {
                        string_table = malloc(string_table_size);
                        if (string_table) {
                            fseek(file, string_table_offset, SEEK_SET);
                            fread(string_table, 1, string_table_size, file);
                        }
                    }
                    
                    int count = 0;
                    for (uint32_t i = 0; i < coff_header.NumberOfSymbols && count < 50; i++) {
                        char name[128] = {0};
                        if (symbols[i].N.Name.Zeroes == 0 && string_table) {
                            uint32_t offset = symbols[i].N.Name.Offset;
                            if (offset < string_table_size) {
                                strncpy(name, string_table + offset, sizeof(name) - 1);
                            }
                        } else {
                            memcpy(name, symbols[i].N.ShortName, 8);
                        }
                        
                        if (name[0] != '\0' && symbols[i].StorageClass == 2) {
                            /* Escape special characters in symbol names */
                            fprintf(dot, "|{");
                            for (int j = 0; name[j] != '\0'; j++) {
                                char c = name[j];
                                if (c == '|' || c == '{' || c == '}' || c == '<' || c == '>' || c == '"' || c == '\\') {
                                    fprintf(dot, "\\%c", c);
                                } else if (c == ' ') {
                                    fprintf(dot, "\\ ");
                                } else {
                                    fprintf(dot, "%c", c);
                                }
                            }
                            fprintf(dot, "|0x%08x}", symbols[i].Value);
                            count++;
                        }
                        i += symbols[i].NumberOfAuxSymbols;
                    }
                    
                    free(string_table);
                    free(symbols);
                }
                
                fprintf(dot, "}\"];\n");
                fprintf(dot, "  sections -> symbols;\n");
            }
            
            fprintf(dot, "}\n");
            fclose(dot);
            printf("\n[+] Generated DOT file: %s\n", dotfile);
        }
    }

    free(data_dirs);
    free(sections);
    fclose(file);
}
