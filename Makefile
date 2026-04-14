arp-spoof: arp-spoof.c
	gcc -o arp-spoof arp-spoof.c -lpcap

clean:
	rm-f arp-spoof
