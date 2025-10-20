all:
	$(CC) -static main.c -lbpf -lelf -lz -lzstd -o xskgen

clean:
	rm xskgen
