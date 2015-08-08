#include <stdio.h>
#include <stdbool.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define IPv4_TYPE 2048
#define IPv6_TYPE 34525
#define PPOE_TYPE 34916

struct ipv6 {
	uint32_t vtcfl;
	uint16_t length;
	uint8_t next_header;
	uint8_t hop_limit;
	struct in6_addr ip_src;
	struct in6_addr ip_dst;
};

void print_ipv6_header(struct ipv6*);
const char* get_protocol_name(int);

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
		// Flags
		bool ipv4_flag = false;
		bool ipv6_flag = false;
		bool ppoe_flag = false;

		// 0. Standard information about packet,
		printf("Packet #: %d\n", count);
		count = count + 1;
		printf("Packet length: %d\n", header.len);

		// 1. Find packet type contained at the start of the packet.
		int packet_type = ((int) (cur_packet[12]) << 8) | (int) cur_packet[13];

		switch(packet_type)
		{
			case IPv4_TYPE:
			printf("Ether type: IPv4\n");
			ipv4_flag = true;
			break;

			case IPv6_TYPE:
			printf("Ether type: IPv6\n");
			ipv6_flag = true;
			break;

			case PPOE_TYPE:
			printf("Ether type: PPOE\n");
			ppoe_flag = true;
			break;

			default:
			printf("Unsupported ether type.\n");
			break;
		}
		
		// 2. Get header info: from/to address, protocol.
		// NOTE: ICMPv6 has header size of 48 bytes, IPv4 (UDP, TCP) has 20 bytes.
		
		if (ipv4_flag) {
			cur_packet += 14;
			struct ip *ip_header = (struct ip*) cur_packet;
			printf("From: %s\n", inet_ntoa(ip_header->ip_src));
			printf("To: %s\n", inet_ntoa(ip_header->ip_dst));
			printf("Protocol: %s\n", get_protocol_name(ip_header->ip_p));
		}
		else if (ipv6_flag) {
			cur_packet += 14;
			struct ipv6 *ipv6_header = (struct ipv6*) cur_packet;
			print_ipv6_header(ipv6_header);
		}
		else if (ppoe_flag) {
			cur_packet += 42;
			struct ipv6 *ipv6_header = (struct ipv6*) cur_packet;
			print_ipv6_header(ipv6_header);
		}

		
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

void print_ipv6_header(struct ipv6* ipv6_header) {
	char srcaddr[32];
	char dstaddr[32];
	inet_ntop(AF_INET6, &ipv6_header->ip_src, srcaddr, sizeof(srcaddr));
	inet_ntop(AF_INET6, &ipv6_header->ip_dst, dstaddr, sizeof(dstaddr));
	printf("From: %s\n", srcaddr);
	printf("To: %s\n", dstaddr);
	printf("Protocol: %s\n", get_protocol_name(ipv6_header->next_header));
}

const char* get_protocol_name(int value) {
	//printf("VALUE: %d\n", value);
	const char *protocol = " ";
	switch(value)
	{
		case 0:
		protocol = "IPv6 Extension - Hop-by-hop";
		return protocol;

		case 6:
		protocol = "TCP";
		return protocol;

		case 17:
		protocol = "UDP";
		return protocol;

		case 43:
		protocol = "IPv6 Extension - Routing";
		return protocol;

		case 44:
		protocol = "IPv6 Extension - ESP";
		return protocol;

		case 50:
		protocol = "IPv6 Extension - Destination options";
		return protocol;

		case 51:
		protocol = "IPv6 Extension - AH";
		return protocol;

		case 58:
		protocol = "ICMPv6";
		return protocol;

		case 60:
		protocol = "IPv6 Extension - Destination options";
		return protocol;

		case 135:
		protocol = "IPv6 Extension - Mobility";
		return protocol;

		default:
		protocol = "Unknown";
		return protocol;
	}
}