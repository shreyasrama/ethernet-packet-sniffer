#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

int main(int argc, char **argv)
{
	struct pcap_pkthdr header; // Header struct for pcap packets
	const u_char *cur_packet;  // The current packet

	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_offline(argv[1], errbuf); // Open pcap file

	// Error check handle here

	FILE *fp = fopen("result.txt", "w");

	while (cur_packet = pcap_next(handle, &header)) {
		printf("Packet length: [%d]\n", header.len);
	}

	return 0;
}