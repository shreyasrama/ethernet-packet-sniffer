#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
//#include <linux/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define IPv4_TYPE 2048
#define IPv6_TYPE 34525

int main(int argc, char **argv)
{
	struct pcap_pkthdr header; // Header struct for pcap packets. See <pcap.h>
	const u_char *cur_packet;  // The current packet

	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_offline(argv[1], errbuf); // Open pcap file
	int count = 1; // Initialise a counter of packets


	// -----------------------
	// Error check handle here
	// -----------------------


	// --------------------------------
	// Potentially write to a file here
	// --------------------------------


	// Loop through packets
	while (cur_packet = pcap_next(handle, &header)) {
		// 0. Standard information about packet,
		printf("Packet #: %d\n", count);
		count = count + 1;
		printf("Packet length: %d\n", header.len);

		// 1. Find packet type contained at the start of the packet.
		int packet_type = ((int) (cur_packet[12]) << 8) | (int) cur_packet[13];

		switch(packet_type)
		{
			case IPv4_TYPE :
			printf("Ether type: IPv4\n");
			break;

			case IPv6_TYPE :
			printf("Ether type: IPv6\n");
			break;

			default :
			printf("Unsupported ether type.\n");
			break;
		}
		
		// 2. Get header info: from/to address, protocol.
		// NOTE: ICMPv6 has header size of 48 bytes, IPv4 (UDP, TCP) has 20 bytes.
		cur_packet += 14;
		struct ip *ip_header = (struct ip*) cur_packet;

		printf("From: %s\n", inet_ntoa(ip_header->ip_src));
		printf("To: %s\n", inet_ntoa(ip_header->ip_dst));

		printf("Protocol: %d\n", ip_header->ip_p);

		// 3. Get packet info: src/dst ports, payload size.
		if (packet_type == IPv4_TYPE) {
			cur_packet += 20;
			struct tcphdr *tcp_header = (struct tcphdr*) cur_packet;
			printf("Src port: %d\n", ntohs(tcp_header->th_sport)); // ntohs() takes a 16-bit number in TCP/IP network byte order and returns in host byte order
			printf("Dst port: %d\n", ntohs(tcp_header->th_dport));
		}
		else {
			printf("Src port: IPv6\n");
			printf("Dst port: IPv6\n");
		}
		
		printf("###############################\n");


	}

	return 0;
}