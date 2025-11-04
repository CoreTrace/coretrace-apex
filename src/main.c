#include "../includes/binary.h"

int main(int ac, char **av)
{
    binary_t *binary = malloc(sizeof(binary_t));
    args_checker(ac, av, binary);
    get_file_type(binary);
    get_file_bits(binary);
    handle_binary(binary);
    free(binary);
    return 0;
}
