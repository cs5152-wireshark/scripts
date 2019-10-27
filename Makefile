CC = gcc
FLAGS = -g -Wall
LIBDEPS = -lgcrypt -lmath
ARGS = sample_dump.txt

openssh_chacha20_poly1305: openssh_chacha20_poly1305.c
	$(CC) $(FLAGS) $(LIBDEPS) $^ -o $@

run: openssh_chacha20_poly1305
	./openssh_chacha20_poly1305 $(ARGS)

clean:
	rm -rf openssh_chacha20_poly1305
