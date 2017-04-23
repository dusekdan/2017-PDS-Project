#define ARP_ETHERNET_HWTYPE 1
#define ARP_IPV4_PROTOTYPE 0x0800
#define ARP_OPERATION_REQUEST 0x0001
#define ARP_OPERATION_REPLY 0x0002
#define NDP_ETHERNET_HWTYPE 1
#define EXIT_SUCCESS 0
#define DEBUG 0
#define ARGUMENT_NUMBER 15
#define DECADIC_BASE 10
#define LONG_OPT_CASE 0
#define MAC_ADDR_LEN 6
#define IPV4_LEN 4
#define IPV6_LEN 16
#define ARP_CURE_REPLIES_COUNT 20
#define IPV6_ALLNODES "ff02::1"

#include <iostream>
#include <vector>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <errno.h>
#include <netinet/icmp6.h>
#include <algorithm>
#include <sstream>

/**
 *	Parameter processing structure (getopts hack)
 */
struct option longopts[] =
{
	{"i", required_argument, 0, 'i'},
	{"t", required_argument, 0, 't'},
	{"p", required_argument, 0, 'p'},
	{"victim1ip", required_argument, 0, 0},
	{"victim2ip", required_argument, 0, 0},
	{"victim1mac", required_argument, 0, 0},
	{"victim2mac", required_argument, 0, 0},
	{0,0,0,0}
};


/**
 *	Parameter holding structure
 */
struct Parameters
{
	std::string interfaceName;
	int 		poisonTimeout;
	int 	    protocol;
	std::string victimIP1;
	std::string victimIP2;
	std::string victimMAC1;
	uint8_t*	victimMAC1Raw[MAC_ADDR_LEN];
	std::string victimMAC2;
	uint8_t*	victimMAC2Raw[MAC_ADDR_LEN];
};
struct Parameters P;


/**
 *	Structure holding information about various local addresses
 */
struct LocalAddr
{
	std::string ipv4AddressLocal;
	std::string ipv6AddressLocal;

	struct sockaddr_in* ipv4Raw;
	struct in6_addr		ipv6Raw;

	uint8_t ipv4Ready[IPV4_LEN];
	uint8_t	ipv6Ready[IPV6_LEN];
	uint8_t	macAddressLocal[MAC_ADDR_LEN];
};
struct LocalAddr addresses;


/**
 * Structure representing ARP Packet
 */
typedef struct ARPPacket
{
	uint16_t	hw_type;
	uint16_t	proto_type;
	uint8_t		hw_addr_len;
	uint8_t		proto_addr_len;
	uint16_t	operation;
	uint8_t		sender_hw_addr[6];		// 1st 2 bytes, 2nd 2 bytes, 3rd 2 bytes
	uint8_t		sender_proto_addr[4];	// Same
	uint8_t		target_hw_addr[6];
	uint8_t		target_proto_addr[4];
} ARPPacket;


/**
 * Structure for neighbor solicitation packet
 */
typedef struct NeighborAdvertisementPacket
{
	nd_neighbor_advert head;
	uint8_t			   type;
	uint8_t			   length;
	uint8_t				MAC[MAC_ADDR_LEN];
} NeighborAdvertisementPacket;


/**
 * Function headers
 */
void processArguments(int argc, char** argv);
void debug_showProcessedArguments();
std::string debug_getProtocolName(int proto);
void extractAddressesForInterface();
void poisonARPCache();
void antidoteARPCache();
void poisonNDPCache();
void antidoteNDPCache();
void preventViolentTermination(int source);
void prepareARPSocketAddress(struct sockaddr_ll* socketAddress, uint8_t* address);
sockaddr_in6 prepareNDPSocketAddress(in6_addr address, std::string interfaceName);
void prepareARPSocketAddress(struct sockaddr_ll* socketAddress, uint8_t* address);
ARPPacket prepareARPResponsePacket(uint8_t* senderMac, uint32_t senderIP, uint8_t* targetMac, uint32_t targetIP);
NeighborAdvertisementPacket prepareNDPAdvertisementPacket(uint8_t* macAddr, in6_addr ip);
void convertDottedMAC(std::string mac, uint8_t* outMac);
void printReadableMACAddress(uint8_t* MAC);
void convertStringToIPv6(std::string ipv6, in6_addr* allNodes);