BPF_CLANG ?= clang
BPF_CFLAGS = -O2 -g -Wall -target bpf -I.

all: spa_xdp.o

spa_xdp.o: spa_xdp.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f *.o
