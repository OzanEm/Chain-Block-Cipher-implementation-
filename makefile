


CC = g++
CFLAGS  = -g


default: hack


hack:  fscrypt.o main.o
	$(CC) $(CFLAGS) -o hack fscrypt.o main.o -lcrypto

fscrypt.o:  fscrypt.cpp fscrypt.h
	$(CC) $(CFLAGS) -c fscrypt.cpp -lcrypto

main.o:	main.cpp
	$(CC) $(CFLAGS) -c main.cpp -lcrypto
