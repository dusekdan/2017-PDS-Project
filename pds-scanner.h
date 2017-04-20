#define ARP_ETHERNET_HWTYPE 1
#define ARP_IPV4_PROTOTYPE 0x0800
#define ARP_OPERATION_REQUEST 0x0001
#define ARP_OPERATION_REPLY 0x0002




#define MAC_ADDR_LEN 6
#define IPV4_LEN 4
#define IPV6_LEN 16

#define CHILD_PROCESS 0


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
 * Structure for discovered devices
 *  
 */
typedef struct devices
{
	uint8_t		macAddress[MAC_ADDR_LEN];
	uint8_t		ipv4Address[IPV4_LEN];
	std::string	ipv6AddressLL;	// TODO Change this to reasonable structures
	std::string	ipv6AddressSTD;
} Devices;
std::vector<Devices> discoveredDevices;