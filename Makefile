all:
	$(CC) -static main.c -lbpf -lelf -lz -o xskgen
