all: main des
	gcc -o DES main.c des.c

main: main.c
	gcc -c main.c

des: des.c des.h
	gcc -c des.c

clean:
	rm DES
