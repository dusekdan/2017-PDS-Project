#define ARP_ETHERNET_HWTYPE 1
#define ARP_IPV4_PROTOTYPE 0x0800
#define ARP_OPERATION_REQUEST 0x0001
#define ARP_OPERATION_REPLY 0x0002
#define NDP_ETHERNET_HWTYPE 1
#define ARGUMENT_NUMBER 5
#define MAC_ADDR_LEN 6
#define IPV4_LEN 4
#define IPV6_LEN 16
#define CHILD_PROCESS 0
#define IPV6_ALLNODES "ff02::1"
#define IPV6_NS_PREFIX_OR_SOMETHING "ff02::1:ff00:0"
#define EXIT_SUCCESS 0
#define DEBUG 0

#include <iostream>
#include <vector>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <string.h>
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
 * Structure for representating PINGv6 Packet
 */
typedef struct ICMPv6Echo
{
	uint8_t		type;
	uint8_t		code;
	uint16_t	checksum;
	uint16_t	identifier;
	uint16_t	sequence_number;
} ICMPv6Echo;


/**
 * Structure for neighbor solicitation packet
 */
typedef struct NeighborSolicitationPacket
{
	nd_neighbor_solicit	head;
	uint8_t				type;
	uint8_t				length;
	uint8_t				MAC[MAC_ADDR_LEN];
} NeighborSolicitationPacket;



/**
 * Structure for neightbor advertisemnt packet
 */
typedef struct NeighborAdvertisementPacket
{
	nd_neighbor_advert head;
	uint8_t			   type;
	uint8_t			   length;
	uint8_t				MAC[MAC_ADDR_LEN];
} NeighborAdvertisementPacket;

/**
 * Structure for discovered devices
 *  
 */
typedef struct devices
{
	uint8_t		macAddress[MAC_ADDR_LEN];
	uint8_t		ipv4Address[IPV4_LEN];
	std::string	ipv6AddressLL;	
	std::string	ipv6AddressSTD;
} Devices;
std::vector<Devices> discoveredDevices;

/**
 *	Parameter holding structure
 */
struct Parameters
{
	std::string interfaceName;
	std::string outputFileName;
};
struct Parameters P;

/**
 *	Structure storing information about different local structures
 */
struct Network
{
	std::string ipv4AddressLocal;
	uint32_t	ipv4Local;
	uint32_t	ipv4NetworkMask;


	struct sockaddr_in* netmask;
	struct sockaddr_in* ipv4;

	uint8_t		macAddressLocal[MAC_ADDR_LEN];

	std::string ipv6AddressLocal;
	struct in6_addr    ipv6AddressLocalRaw;
	//struct in_addr ipv4;
};
struct Network addresses;


/**
 * Function headers
 */
void extractAddressesForInterface();
void extractAllInterfaceAddresses();
void discoverDevicesARP();
void discoverDevicesNDP();
std::string getReadableIPv4Address(uint32_t address);
std::string getReadableIPv4Address(uint8_t* address);
void printReadableMACAddress(uint8_t* MAC);
void debug_showDiscoveredDevices();
void processArguments(int argc, char** argv);
void prepareARPSocketAddress(struct sockaddr_ll* socketAddress, uint8_t* address);
sockaddr_in6 prepareNDPSocketAddress(in6_addr address, std::string interfaceName);
std::string convertIPv6ToString(in6_addr ipv6);
void convertStringToIPv6(std::string ipv6, in6_addr* allNodes);
void debug_showDiscoveredIPv6();
std::vector<in6_addr> discoveredPingIPv6;