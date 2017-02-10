all:
	gcc -Wall -o main main.c -lpcap 
clean:
	rm -f sniffer.o
