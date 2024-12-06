CC=gcc
CFLAGS=-Wall -Werror -Wno-unused-result -std=c2x -g -fsanitize=address -Wvla 
LDFLAGS=-lm -lpthread
INCLUDE=-Iinclude

.PHONY: clean

pkgmain: src/pkgmain.c src/chk/pkgchk.c src/crypt/sha256.c 
	$(CC) $^ -Iinclude $(CFLAGS) $(LDFLAGS) -o $@

pkgchk.o: src/chk/pkgchk.c
	$(CC) -c $^ $(INCLUDE) $(CFLAGS) 

sha256.o: src/crypt/sha256.c
	$(CC) -c $^ $(INCLUDE) $(CFLAGS) 

pkgchecker: src/pkgmain.c src/chk/pkgchk.c
	$(CC) $^ $(INCLUDE) $(CFLAGS) $(LDFLAGS) -o $@

btide: src/btide.c
	$(CC) $^ $(INCLUDE) $(CFLAGS) $(LDFLAGS) -o $@

p1tests:
	bash p1test.sh

p2tests:
	bash p2test.sh

clean:
	rm -f *.o
	rm -f pkgmain
	rm -f pkgchecker
    
