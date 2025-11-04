#include "../includes/binary.h"

char *commands[5] = {"help","scan", "functions", "variables", NULL}; //Available commands
unsigned char pe_signature[4] = {0x50, 0x45, 0x00, 0x00}; // PE file signature
unsigned char elf_signature[4] = {0x7F, 0x45, 0x4C, 0x46}; // ELF file signature

void args_checker(int ac, char **av, binary_t *binary)
{
    /* Accept either:
       - program help                    (ac == 2)
       - program <cmd> <file>            (ac == 3)
       - program <cmd> <file> --report   (ac == 4)
       Any other arity is a usage error. */
    if (ac < 2 || ac > 4) {
        fprintf(stderr, "Usage: %s <command> <file_path> [--report]\n or %s help to list commands\n", av[0], av[0]);
        exit(EXIT_FAILURE);
    }

    /* Initialize report flag */
    binary->generate_report = false;

    /* command is always av[1] when ac >= 2 */
    binary->command = av[1];

    /* If user asked for help, allow ac == 2 and print help immediately. */
    if (strcmp(binary->command, "help") == 0) {
        fprintf(stdout, "Available commands:\n");
        for (int i = 1; commands[i] != NULL; i++) {
            fprintf(stdout, " - %s\n", commands[i]);
        }
        fprintf(stdout, "\nOptional flags:\n");
        fprintf(stdout, " --report : Generate a .dot graph file with symbol tables\n");
        exit(EXIT_SUCCESS);
    }

    /* For non-help commands, we require a file path (ac >= 3). */
    if (ac < 3) {
        fprintf(stderr, "Usage: %s <command> <file_path> [--report]\n", av[0]);
        exit(EXIT_FAILURE);
    }

    binary->file_path = av[2];

    /* Check for --report flag */
    if (ac == 4) {
        if (strcmp(av[3], "--report") == 0) {
            binary->generate_report = true;
            fprintf(stdout, "Report generation enabled. Will create .dot file.\n");
        } else {
            fprintf(stderr, "Error: Unknown flag '%s'. Use --report to generate graph.\n", av[3]);
            exit(EXIT_FAILURE);
        }
    }

    int recognized = 0;
    for (int i = 0; commands[i] != NULL; i++) {
        if (strcmp(binary->command, commands[i]) == 0) {
            recognized = 1;
            break;
        }
    }

    if (recognized) {
        fprintf(stdout, "Command '%s' recognized. Proceeding with file: %s\n", binary->command, binary->file_path);
        return;
    } else {
        fprintf(stderr, "Error: Unknown command '%s'. Valid commands are: help, scan, functions, variables.\n", binary->command);
        exit(EXIT_FAILURE);
    }
}

void get_file_type(binary_t *binary)
{
    FILE *file = fopen(binary->file_path, "rb");
    if (!file)
    {
        fprintf(stderr, "Error: Could not open file %s\n", binary->file_path);
        exit(EXIT_FAILURE);
    }

    unsigned char buffer[4];
    if (fread(buffer, 1, 4, file) != 4) {
        fprintf(stderr, "Error: Could not read header from %s\n", binary->file_path);
        fclose(file);
        exit(EXIT_FAILURE);
    }

    /* First, check for ELF (magic at file start) */
    if (memcmp(buffer, elf_signature, 4) == 0)
    {
        binary->file_type = "ELF";
        fprintf(stdout, "File type detected: ELF\n");
        fclose(file);
        return;
    }

    /* Check for DOS MZ header; if present, locate PE header via e_lfanew at offset 0x3C */
    if (buffer[0] == 'M' && buffer[1] == 'Z') {
        /* Read e_lfanew (DWORD at offset 0x3C) */
        if (fseek(file, 0x3C, SEEK_SET) != 0) {
            fprintf(stderr, "Error: fseek failed for %s\n", binary->file_path);
            fclose(file);
            exit(EXIT_FAILURE);
        }

        uint32_t e_lfanew = 0;
        if (fread(&e_lfanew, sizeof(e_lfanew), 1, file) != 1) {
            fprintf(stderr, "Error: could not read e_lfanew from %s\n", binary->file_path);
            fclose(file);
            exit(EXIT_FAILURE);
        }

        /* e_lfanew is little-endian in PE files; on little-endian hosts this is fine */
        if (fseek(file, (long)e_lfanew, SEEK_SET) != 0) {
            fprintf(stderr, "Error: could not seek to PE header at 0x%X in %s\n", e_lfanew, binary->file_path);
            fclose(file);
            exit(EXIT_FAILURE);
        }

        unsigned char pe[4];
        if (fread(pe, 1, 4, file) != 4) {
            fprintf(stderr, "Error: could not read PE signature from %s\n", binary->file_path);
            fclose(file);
            exit(EXIT_FAILURE);
        }

        if (memcmp(pe, pe_signature, 4) == 0) {
            binary->file_type = "PE";
            fprintf(stdout, "File type detected: PE\n");
            fclose(file);
            return;
        }
    }

    /* Unknown */
    binary->file_type = "Unknown";
    fprintf(stderr, "Unable to determine file type for %s aborting.\n", binary->file_path);
    fclose(file);
    exit(EXIT_FAILURE);
}

void get_file_bits(binary_t *binary)
{
    FILE *file = fopen(binary->file_path, "rb");
    if (!file)
    {
        fprintf(stderr, "Error: Could not open file %s\n", binary->file_path);
        exit(EXIT_FAILURE);
    }

    unsigned char buffer[2];

    if (strcmp(binary->file_type, "ELF") == 0)
    {
        /* For ELF, the class byte is at offset 4 */
        if (fseek(file, 4, SEEK_SET) != 0 ||
            fread(buffer, 1, 1, file) != 1)
        {
            fprintf(stderr, "Error: Could not read ELF class from %s\n", binary->file_path);
            fclose(file);
            exit(EXIT_FAILURE);
        }

        if (buffer[0] == 1)
        {
            binary->architecture = 32;
            fprintf(stdout, "Architecture detected: 32-bit\n");
        }
        else if (buffer[0] == 2)
        {
            binary->architecture = 64;
            fprintf(stdout, "Architecture detected: 64-bit\n");
        }
        else
        {
            fprintf(stderr, "Error: Unknown ELF class in %s\n", binary->file_path);
            fclose(file);
            exit(EXIT_FAILURE);
        }
    }
    else if (strcmp(binary->file_type, "PE") == 0)
    {
        /* For PE, the machine type is at offset 4 from the PE header */
        if (fseek(file, 0x3C, SEEK_SET) != 0)
        {
            fprintf(stderr, "Error: fseek failed for %s\n", binary->file_path);
            fclose(file);
            exit(EXIT_FAILURE);
        }

        uint32_t e_lfanew = 0;
        if (fread(&e_lfanew, sizeof(e_lfanew), 1, file) != 1)
        {
            fprintf(stderr, "Error: could not read e_lfanew from %s\n", binary->file_path);
            fclose(file);
            exit(EXIT_FAILURE);
        }

        if (fseek(file, (long)(e_lfanew + 4), SEEK_SET) != 0 ||
            fread(buffer, 2, 1, file) != 1)
        {
            fprintf(stderr, "Error: Could not read PE machine type from %s\n", binary->file_path);
            fclose(file);
            exit(EXIT_FAILURE);
        }
        uint16_t machine = buffer[0] | (buffer[1] << 8);
        if (machine == 0x014c) // IMAGE_FILE_MACHINE_I386
        {
            binary->architecture = 32;
            fprintf(stdout, "Architecture detected: 32-bit\n");
        }
        else if (machine == 0x8664) // IMAGE_FILE_MACHINE_AMD64
        {
            binary->architecture = 64;
            fprintf(stdout, "Architecture detected: 64-bit\n");
        }
        else
        {
            fprintf(stderr, "Error: Unknown PE machine type in %s\n", binary->file_path);
            fclose(file);
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        fprintf(stderr, "Error: Unsupported file type %s for architecture detection\n", binary->file_type);
        fclose(file);
        exit(EXIT_FAILURE);
    }
    fclose(file);
}
