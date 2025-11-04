#include "../includes/binary.h"

void handle_binary(binary_t *binary)
{
	if (!binary || !binary->file_type || !binary->file_path) {
		fprintf(stderr, "handle_binary: invalid argument\n");
		return;
	}

	if (strcmp(binary->file_type, "ELF") == 0) {
		parse_elf(binary->file_path, binary->generate_report);
		return;
	}

	if (strcmp(binary->file_type, "PE") == 0) {
		parse_pe(binary->file_path, binary->generate_report);
		return;
	}

	fprintf(stderr, "handle_binary: unsupported file type '%s'\n", binary->file_type);
}