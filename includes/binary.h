#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct binary_s
{
    char const *file_path;
    char const *command;
    char const *file_type;
    short architecture;
    bool generate_report;  /* 1 if --report flag is set, 0 otherwise */
} binary_t;

void args_checker(int ac, char **av, binary_t *binary);
void get_file_type(binary_t *binary);
void get_file_bits(binary_t *binary);
void handle_binary(binary_t *binary);

/* Binary parsers */
void parse_elf(const char *filepath, int generate_dot);
void parse_pe(const char *filepath, int generate_dot);
