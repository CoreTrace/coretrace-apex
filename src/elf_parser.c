#include "../includes/binary.h"
#include <elf.h>

/* Helper to detect if ELF is 32 or 64 bit */
static int is_elf64(FILE *file)
{
    unsigned char e_ident[EI_NIDENT];
    fseek(file, 0, SEEK_SET);
    if (fread(e_ident, 1, EI_NIDENT, file) != EI_NIDENT) {
        return -1;
    }
    return (e_ident[EI_CLASS] == ELFCLASS64) ? 1 : 0;
}

/* Parse ELF32 */
static void parse_elf32(FILE *file, const char *filepath, int generate_dot)
{
    Elf32_Ehdr ehdr;
    fseek(file, 0, SEEK_SET);
    if (fread(&ehdr, 1, sizeof(ehdr), file) != sizeof(ehdr)) {
        fprintf(stderr, "Failed to read ELF32 header\n");
        return;
    }

    printf("\n=== ELF32 Header ===\n");
    printf("Entry point: 0x%08x\n", ehdr.e_entry);
    printf("Section headers: %u (offset: 0x%x)\n", ehdr.e_shnum, ehdr.e_shoff);

    if (ehdr.e_shnum == 0) {
        printf("No sections found\n");
        return;
    }

    /* Read section headers */
    Elf32_Shdr *shdrs = malloc(sizeof(Elf32_Shdr) * ehdr.e_shnum);
    if (!shdrs) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }

    fseek(file, ehdr.e_shoff, SEEK_SET);
    if (fread(shdrs, sizeof(Elf32_Shdr), ehdr.e_shnum, file) != ehdr.e_shnum) {
        fprintf(stderr, "Failed to read section headers\n");
        free(shdrs);
        return;
    }

    /* Read section string table */
    char *shstrtab = NULL;
    if (ehdr.e_shstrndx < ehdr.e_shnum) {
        Elf32_Shdr *shstrtab_hdr = &shdrs[ehdr.e_shstrndx];
        shstrtab = malloc(shstrtab_hdr->sh_size);
        if (shstrtab) {
            fseek(file, shstrtab_hdr->sh_offset, SEEK_SET);
            fread(shstrtab, 1, shstrtab_hdr->sh_size, file);
        }
    }

    printf("\n=== Sections ===\n");
    printf("%-20s %-12s %-12s %-10s\n", "Name", "Type", "Address", "Size");
    printf("%-20s %-12s %-12s %-10s\n", "----", "----", "-------", "----");

    for (int i = 0; i < ehdr.e_shnum; i++) {
        const char *name = shstrtab ? shstrtab + shdrs[i].sh_name : "(unknown)";
        printf("%-20s 0x%08x   0x%08x   %u\n", 
               name, shdrs[i].sh_type, shdrs[i].sh_addr, shdrs[i].sh_size);
    }

    /* Find symbol tables */
    for (int i = 0; i < ehdr.e_shnum; i++) {
        if (shdrs[i].sh_type != SHT_SYMTAB && shdrs[i].sh_type != SHT_DYNSYM) {
            continue;
        }

        const char *table_name = shstrtab ? shstrtab + shdrs[i].sh_name : "(unknown)";
        printf("\n=== Symbol Table: %s ===\n", table_name);

        Elf32_Sym *syms = malloc(shdrs[i].sh_size);
        if (!syms) continue;

        fseek(file, shdrs[i].sh_offset, SEEK_SET);
        fread(syms, 1, shdrs[i].sh_size, file);

        int sym_count = shdrs[i].sh_size / sizeof(Elf32_Sym);

        /* Read string table for symbols */
        char *strtab = NULL;
        if (shdrs[i].sh_link < ehdr.e_shnum) {
            Elf32_Shdr *strtab_hdr = &shdrs[shdrs[i].sh_link];
            strtab = malloc(strtab_hdr->sh_size);
            if (strtab) {
                fseek(file, strtab_hdr->sh_offset, SEEK_SET);
                fread(strtab, 1, strtab_hdr->sh_size, file);
            }
        }

        printf("%-40s %-12s %-10s %-10s\n", "Name", "Type", "Address", "Size");
        printf("%-40s %-12s %-10s %-10s\n", "----", "----", "-------", "----");

        for (int j = 0; j < sym_count; j++) {
            unsigned char type = ELF32_ST_TYPE(syms[j].st_info);
            const char *name = strtab ? strtab + syms[j].st_name : "(unknown)";
            
            if (name[0] == '\0' || syms[j].st_name == 0) continue;

            const char *type_str = "OTHER";
            if (type == STT_FUNC) type_str = "FUNC";
            else if (type == STT_OBJECT) type_str = "OBJECT";
            else if (type == STT_NOTYPE) continue; // Skip undefined

            printf("%-40s %-12s 0x%08x   %u\n", 
                   name, type_str, syms[j].st_value, syms[j].st_size);
        }

        free(strtab);
        free(syms);
    }

    /* Generate .dot file if requested */
    if (generate_dot) {
        char dotfile[512];
        snprintf(dotfile, sizeof(dotfile), "%s_elf32.dot", filepath);
        FILE *dot = fopen(dotfile, "w");
        if (dot) {
            fprintf(dot, "digraph ELF32 {\n");
            fprintf(dot, "  rankdir=LR;\n");
            fprintf(dot, "  node [shape=record];\n\n");
            
            /* Sections node */
            fprintf(dot, "  sections [label=\"{Sections");
            for (int i = 0; i < ehdr.e_shnum; i++) {
                const char *name = shstrtab ? shstrtab + shdrs[i].sh_name : "unknown";
                fprintf(dot, "|{%s|0x%08x|%u}", name, shdrs[i].sh_addr, shdrs[i].sh_size);
            }
            fprintf(dot, "}\"];\n\n");
            
            /* Symbol tables */
            for (int i = 0; i < ehdr.e_shnum; i++) {
                if (shdrs[i].sh_type != SHT_SYMTAB && shdrs[i].sh_type != SHT_DYNSYM) continue;
                
                const char *table_name = shstrtab ? shstrtab + shdrs[i].sh_name : "unknown";
                fprintf(dot, "  sym%d [label=\"{%s", i, table_name);
                
                Elf32_Sym *syms = malloc(shdrs[i].sh_size);
                if (!syms) continue;
                
                fseek(file, shdrs[i].sh_offset, SEEK_SET);
                fread(syms, 1, shdrs[i].sh_size, file);
                int sym_count = shdrs[i].sh_size / sizeof(Elf32_Sym);
                
                char *strtab = NULL;
                if (shdrs[i].sh_link < ehdr.e_shnum) {
                    Elf32_Shdr *strtab_hdr = &shdrs[shdrs[i].sh_link];
                    strtab = malloc(strtab_hdr->sh_size);
                    if (strtab) {
                        fseek(file, strtab_hdr->sh_offset, SEEK_SET);
                        fread(strtab, 1, strtab_hdr->sh_size, file);
                    }
                }
                
                for (int j = 0; j < sym_count && j < 50; j++) {
                    unsigned char type = ELF32_ST_TYPE(syms[j].st_info);
                    const char *name = strtab ? strtab + syms[j].st_name : "unknown";
                    if (name[0] == '\0') continue;
                    
                    const char *type_str = "?";
                    if (type == STT_FUNC) type_str = "F";
                    else if (type == STT_OBJECT) type_str = "O";
                    else continue;
                    
                    fprintf(dot, "|{%s|%s|0x%08x}", name, type_str, syms[j].st_value);
                }
                
                fprintf(dot, "}\"];\n");
                fprintf(dot, "  sections -> sym%d;\n", i);
                
                free(strtab);
                free(syms);
            }
            
            fprintf(dot, "}\n");
            fclose(dot);
            printf("\n[+] Generated DOT file: %s\n", dotfile);
        }
    }

    free(shstrtab);
    free(shdrs);
}

/* Parse ELF64 */
static void parse_elf64(FILE *file, const char *filepath, int generate_dot)
{
    Elf64_Ehdr ehdr;
    fseek(file, 0, SEEK_SET);
    if (fread(&ehdr, 1, sizeof(ehdr), file) != sizeof(ehdr)) {
        fprintf(stderr, "Failed to read ELF64 header\n");
        return;
    }

    printf("\n=== ELF64 Header ===\n");
    printf("Entry point: 0x%016lx\n", ehdr.e_entry);
    printf("Section headers: %u (offset: 0x%lx)\n", ehdr.e_shnum, ehdr.e_shoff);

    if (ehdr.e_shnum == 0) {
        printf("No sections found\n");
        return;
    }

    /* Read section headers */
    Elf64_Shdr *shdrs = malloc(sizeof(Elf64_Shdr) * ehdr.e_shnum);
    if (!shdrs) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }

    fseek(file, ehdr.e_shoff, SEEK_SET);
    if (fread(shdrs, sizeof(Elf64_Shdr), ehdr.e_shnum, file) != ehdr.e_shnum) {
        fprintf(stderr, "Failed to read section headers\n");
        free(shdrs);
        return;
    }

    /* Read section string table */
    char *shstrtab = NULL;
    if (ehdr.e_shstrndx < ehdr.e_shnum) {
        Elf64_Shdr *shstrtab_hdr = &shdrs[ehdr.e_shstrndx];
        shstrtab = malloc(shstrtab_hdr->sh_size);
        if (shstrtab) {
            fseek(file, shstrtab_hdr->sh_offset, SEEK_SET);
            fread(shstrtab, 1, shstrtab_hdr->sh_size, file);
        }
    }

    printf("\n=== Sections ===\n");
    printf("%-20s %-12s %-18s %-10s\n", "Name", "Type", "Address", "Size");
    printf("%-20s %-12s %-18s %-10s\n", "----", "----", "-------", "----");

    for (int i = 0; i < ehdr.e_shnum; i++) {
        const char *name = shstrtab ? shstrtab + shdrs[i].sh_name : "(unknown)";
        printf("%-20s 0x%08x   0x%016lx   %lu\n", 
               name, shdrs[i].sh_type, shdrs[i].sh_addr, shdrs[i].sh_size);
    }

    /* Find symbol tables */
    for (int i = 0; i < ehdr.e_shnum; i++) {
        if (shdrs[i].sh_type != SHT_SYMTAB && shdrs[i].sh_type != SHT_DYNSYM) {
            continue;
        }

        const char *table_name = shstrtab ? shstrtab + shdrs[i].sh_name : "(unknown)";
        printf("\n=== Symbol Table: %s ===\n", table_name);

        Elf64_Sym *syms = malloc(shdrs[i].sh_size);
        if (!syms) continue;

        fseek(file, shdrs[i].sh_offset, SEEK_SET);
        fread(syms, 1, shdrs[i].sh_size, file);

        int sym_count = shdrs[i].sh_size / sizeof(Elf64_Sym);

        /* Read string table for symbols */
        char *strtab = NULL;
        if (shdrs[i].sh_link < ehdr.e_shnum) {
            Elf64_Shdr *strtab_hdr = &shdrs[shdrs[i].sh_link];
            strtab = malloc(strtab_hdr->sh_size);
            if (strtab) {
                fseek(file, strtab_hdr->sh_offset, SEEK_SET);
                fread(strtab, 1, strtab_hdr->sh_size, file);
            }
        }

        printf("%-40s %-12s %-18s %-10s\n", "Name", "Type", "Address", "Size");
        printf("%-40s %-12s %-18s %-10s\n", "----", "----", "-------", "----");

        for (int j = 0; j < sym_count; j++) {
            unsigned char type = ELF64_ST_TYPE(syms[j].st_info);
            const char *name = strtab ? strtab + syms[j].st_name : "(unknown)";
            
            if (name[0] == '\0' || syms[j].st_name == 0) continue;

            const char *type_str = "OTHER";
            if (type == STT_FUNC) type_str = "FUNC";
            else if (type == STT_OBJECT) type_str = "OBJECT";
            else if (type == STT_NOTYPE) continue; // Skip undefined

            printf("%-40s %-12s 0x%016lx   %lu\n", 
                   name, type_str, syms[j].st_value, syms[j].st_size);
        }

        free(strtab);
        free(syms);
    }

    /* Generate .dot file if requested */
    if (generate_dot) {
        char dotfile[512];
        snprintf(dotfile, sizeof(dotfile), "%s_elf64.dot", filepath);
        FILE *dot = fopen(dotfile, "w");
        if (dot) {
            fprintf(dot, "digraph ELF64 {\n");
            fprintf(dot, "  rankdir=LR;\n");
            fprintf(dot, "  node [shape=record];\n\n");
            
            /* Sections node */
            fprintf(dot, "  sections [label=\"{Sections");
            for (int i = 0; i < ehdr.e_shnum; i++) {
                const char *name = shstrtab ? shstrtab + shdrs[i].sh_name : "unknown";
                fprintf(dot, "|{%s|0x%016lx|%lu}", name, shdrs[i].sh_addr, shdrs[i].sh_size);
            }
            fprintf(dot, "}\"];\n\n");
            
            /* Symbol tables */
            for (int i = 0; i < ehdr.e_shnum; i++) {
                if (shdrs[i].sh_type != SHT_SYMTAB && shdrs[i].sh_type != SHT_DYNSYM) continue;
                
                const char *table_name = shstrtab ? shstrtab + shdrs[i].sh_name : "unknown";
                fprintf(dot, "  sym%d [label=\"{%s", i, table_name);
                
                Elf64_Sym *syms = malloc(shdrs[i].sh_size);
                if (!syms) continue;
                
                fseek(file, shdrs[i].sh_offset, SEEK_SET);
                fread(syms, 1, shdrs[i].sh_size, file);
                int sym_count = shdrs[i].sh_size / sizeof(Elf64_Sym);
                
                char *strtab = NULL;
                if (shdrs[i].sh_link < ehdr.e_shnum) {
                    Elf64_Shdr *strtab_hdr = &shdrs[shdrs[i].sh_link];
                    strtab = malloc(strtab_hdr->sh_size);
                    if (strtab) {
                        fseek(file, strtab_hdr->sh_offset, SEEK_SET);
                        fread(strtab, 1, strtab_hdr->sh_size, file);
                    }
                }
                
                for (int j = 0; j < sym_count && j < 50; j++) {
                    unsigned char type = ELF64_ST_TYPE(syms[j].st_info);
                    const char *name = strtab ? strtab + syms[j].st_name : "unknown";
                    if (name[0] == '\0') continue;
                    
                    const char *type_str = "?";
                    if (type == STT_FUNC) type_str = "F";
                    else if (type == STT_OBJECT) type_str = "O";
                    else continue;
                    
                    fprintf(dot, "|{%s|%s|0x%016lx}", name, type_str, syms[j].st_value);
                }
                
                fprintf(dot, "}\"];\n");
                fprintf(dot, "  sections -> sym%d;\n", i);
                
                free(strtab);
                free(syms);
            }
            
            fprintf(dot, "}\n");
            fclose(dot);
            printf("\n[+] Generated DOT file: %s\n", dotfile);
        }
    }

    free(shstrtab);
    free(shdrs);
}

void parse_elf(const char *filepath, int generate_dot)
{
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        fprintf(stderr, "Failed to open file: %s\n", filepath);
        return;
    }

    int is64 = is_elf64(file);
    if (is64 < 0) {
        fprintf(stderr, "Failed to determine ELF class\n");
        fclose(file);
        return;
    }

    if (is64) {
        parse_elf64(file, filepath, generate_dot);
    } else {
        parse_elf32(file, filepath, generate_dot);
    }

    fclose(file);
}
