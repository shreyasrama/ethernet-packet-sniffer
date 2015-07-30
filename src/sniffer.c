#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
//#include <linux/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

int main(int argc, char **argv)
{
	struct pcap_pkthdr header; // Header struct for pcap packets. See <pcap.h>
	const u_char *cur_packet;  // The current packet

	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_offline(argv[1], errbuf); // Open pcap file
	int count = 1; // Initialise a counter of packets

	// Error check handle here

	FILE *fp = fopen("result.txt", "w");

	while (cur_packet = pcap_next(handle, &header)) {
		printf("Packet #: %d\n", count);
		count = count + 1;

		printf("Packet length: %d\n", header.len);

		// 1. Find packet type contained at the start of the packet.
		int packet_type = ((int) (cur_packet[12]) << 8) | (int) cur_packet[13];
		if (packet_type == 2048) {
			printf("Ether type: IPv4\n");
		}
		else {
			printf("Ether type: IPv6\n");	
		}
		
		// 2. Get header info: IP version, payload length, source, destination
		// NOTE: ICMPv6 has header size of 48 bytes, IPv4 (UDP, TCP) has 20 bytes.
		cur_packet += 14;
		struct ip *ip_header = (struct ip*) cur_packet;

		printf("From: ?\n");
		printf("To: ?\n");

		printf("Protocol: %d\n", ip_header->ip_p);

		// 3. Get packet info: 
		if (packet_type == 2048) {
			cur_packet += 20;
			struct tcphdr *tcp_header = (struct tcphdr*) cur_packet;
			printf("Src port: %d\n", ntohs(tcp_header->th_sport));
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