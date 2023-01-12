NAME = wrapper.exe
SRC = $(addprefix src/, main.c loader.c utils.c )
OBJ = ${SRC:.c=.o}
CC = x86_64-w64-mingw32-gcc

all : ${NAME}

${NAME}: ${OBJ}
	${CC} ${OBJ} -o ${NAME}

%.o: %.c
	${CC} -c ${<} -o ${@} ${DEBUG}

clean:
	rm -rf ${OBJ}

fclean: clean
	rm -rf ${NAME}

re: fclean all

.PH0NY: re fclean clean all