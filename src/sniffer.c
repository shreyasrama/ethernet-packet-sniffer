#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

int main(int argc, char **argv)
{
	struct pcap_pkthdr header; // Header struct for pcap packets. See <pcap.h>
	const u_char *cur_packet;  // The current packet

	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_offline(argv[1], errbuf); // Open pcap file

	// Error check handle here

	FILE *fp = fopen("result.txt", "w");

	while (cur_packet = pcap_next(handle, &header)) {
		printf("Packet length: [%d]\n", header.len);

		// 1. Find packet type contained at the start of the packet.
		int packet_type = ((int) (cur_packet[12]) << 8) | (int) cur_packet[13];
		printf("IP type: [%d]\n", packet_type);

		// 2. Get header info: IP version, payload length, source, destination
		// NOTE: ICMPv6 has header size of 48 bytes, IPv4 (UDP, TCP) has 20 bytes.
	}

	return 0;
}