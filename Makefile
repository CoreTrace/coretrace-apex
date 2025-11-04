CC = gcc

SOURCES = src/main.c \
		  src/file_manager.c \
		  src/binary_handler.c \
		  src/elf_parser.c \
		  src/pe_parser.c \

INCLUDES = includes/binary.h

OBJECTS = $(SOURCES:.c=.o)

NAME = coretrace-apex

CFLAGS = -W -Wall -Wextra -Werror

all: $(NAME)
$(NAME): $(OBJECTS) $(INCLUDES)
	$(CC) $(CFLAGS) -o $(NAME) $(OBJECTS)

clean:
	rm -f $(OBJECTS)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re
