#include <stdio.h>
#include <stdbool.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define IPv4_TYPE 2048
#define IPv6_TYPE 34525
#define PPOE_TYPE 34916

typedef enum {TCP, UDP, ICMP, ICMPv6, UNKNOWN, EXTH} protocol_ver;
protocol_ver cur_protocol = UNKNOWN;

struct ipv6 {
	uint32_t vtcfl;
	uint16_t length;
	uint8_t next_header;
	uint8_t hop_limit;
	struct in6_addr ip_src;
	struct in6_addr ip_dst;
};

void print_ipv6_header(struct ipv6*);
void print_tcp_header(struct tcphdr*);
void print_udp_header(struct udphdr*);
void print_icmp_header(struct icmp*, protocol_ver);
const char* get_protocol_name(int);
const char* get_icmpv4_code(int);
const char* get_icmpv6_code(int);

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

		
		// 3. Get packet info: src/dst ports, ICMP info.
		// IPv4
		if (ipv4_flag && cur_protocol == TCP) {
			cur_packet += 20;
			struct tcphdr *tcp_header = (struct tcphdr*) cur_packet;
			print_tcp_header(tcp_header);
		}
		else if (ipv4_flag && cur_protocol == UDP) {
			cur_packet += 20;
			struct udphdr *udp_header = (struct udphdr*) cur_packet;
			print_udp_header(udp_header);
		}
		else if (ipv4_flag && cur_protocol == ICMP) {
			cur_packet += 20;
			struct icmp *icmp_header = (struct icmp*) cur_packet;
			print_icmp_header(icmp_header, ICMP);
		}
		// IPv6
		else if (ipv6_flag && cur_protocol == TCP) {
			cur_packet += 40;
			struct tcphdr *tcp_header = (struct tcphdr*) cur_packet;
			print_tcp_header(tcp_header);
		}
		else if (ipv6_flag && cur_protocol == UDP) {
			cur_packet += 40;
			struct udphdr *udp_header = (struct udphdr*) cur_packet;
			print_udp_header(udp_header);
		}
		else if (ipv6_flag && cur_protocol == ICMPv6) {
			cur_packet += 40;
			struct icmp *icmp_header = (struct icmp*) cur_packet;
			print_icmp_header(icmp_header, ICMPv6);
		}
		
		printf("\n");
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

void print_tcp_header(struct tcphdr* tcp_header) {
	printf("Src port: %d\n", ntohs(tcp_header->th_sport)); // ntohs() takes a 16-bit number in TCP/IP network byte order and returns in host byte order
	printf("Dst port: %d\n", ntohs(tcp_header->th_dport));
}

void print_udp_header(struct udphdr* udp_header) {
	printf("Src port: %d\n", ntohs(udp_header->uh_sport)); // ntohs() takes a 16-bit number in TCP/IP network byte order and returns in host byte order
	printf("Dst port: %d\n", ntohs(udp_header->uh_dport));
}

void print_icmp_header(struct icmp* icmp_header, protocol_ver version) {
	if (version == ICMP) {
		printf("ICMP type %d: %s\n", icmp_header->icmp_type, get_icmpv4_code(icmp_header->icmp_type));
	}
	else if (version == ICMPv6) {
		printf("ICMPv6 type %d: %s\n", icmp_header->icmp_type, get_icmpv6_code(icmp_header->icmp_type));
	}
}

// Uses a protocol number and returns a string based off that number from a subset of protocols.
const char* get_protocol_name(int value) {
	//printf("VALUE: %d\n", value);
	const char *protocol = " ";
	switch(value)
	{
		case 0:
		protocol = "IPv6 Extension - Hop-by-hop";
		cur_protocol = EXTH;
		return protocol;

		case 1:
		protocol = "ICMP";
		cur_protocol = ICMP;
		return protocol;

		case 6:
		protocol = "TCP";
		cur_protocol = TCP;
		return protocol;

		case 17:
		protocol = "UDP";
		cur_protocol = UDP;
		return protocol;

		case 43:
		protocol = "IPv6 Extension - Routing";
		cur_protocol = EXTH;
		return protocol;

		case 44:
		protocol = "IPv6 Extension - ESP";
		cur_protocol = EXTH;
		return protocol;

		case 50:
		protocol = "IPv6 Extension - Destination options";
		cur_protocol = EXTH;
		return protocol;

		case 51:
		protocol = "IPv6 Extension - AH";
		cur_protocol = EXTH;
		return protocol;

		case 58:
		protocol = "ICMPv6";
		cur_protocol = ICMPv6;
		return protocol;

		case 60:
		protocol = "IPv6 Extension - Destination options";
		cur_protocol = EXTH;
		return protocol;

		case 135:
		protocol = "IPv6 Extension - Mobility";
		cur_protocol = EXTH;
		return protocol;

		default:
		protocol = "Unknown";
		cur_protocol = UNKNOWN;
		return protocol;
	}
}

const char* get_icmpv4_code(int value) {
	const char *code = " ";
	switch(value)
	{
		case 0:
		code = "Echo reply (used to ping)";
		return code;

		case 8:
		code = "Echo request (used to ping)";
		return code;

		default:
		code = "Unknown";
		return code;
	}
}

const char* get_icmpv6_code(int value) {
	const char *code = " ";
	switch(value)
	{
		case 134:
		code = "Router Advertisement (NDP)";
		return code;

		default:
		code = "Unknown";
		return code;
	}
}