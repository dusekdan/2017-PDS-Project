#include "pds-scanner.h"

/**
 *	Application entry point
 */
int main(int argc, char **argv)
{
	// Process parameters
	processArguments(argc, argv);
	
	// Extract required information from provided interface and store it to global variable/proper structure
	extractAddressesForInterface();

	// Initiate ARP scanning (if applicable) - IPv4
	discoverDevicesARP();

	// Initiate NDP scanning (if applicable) - IPv6
	discoverDevicesNDP();

	// Show discovered devices to user
	debug_showDiscoveredDevices();

	return EXIT_SUCCESS;

}


/**
 *	Processes parameters supplied from commandline (using getopts() library)
 */
void processArguments(int argc, char** argv)
{
	if (argc != ARGUMENT_NUMBER)
	{
		std::cerr << "Incorrect arguments supplied. Try ./pds-scanner -i interfaceName -f outputFileName.xml" << std::endl;
		exit(2);
	}

	int ch;
	while ((ch = getopt(argc, argv, "i:f:")) != -1)
	{
		switch (ch)
		{
			case 'i':
				P.interfaceName = optarg;
				break;
			case 'f':
				P.outputFileName = optarg;
				break;
		}
	}
}


/**
 *	This coding masterpiece very clumsily computes neighbor solicited-node multicast address
 *	Even reading the previous line hurts me, let alone reading the code again. It pretty much
 *  does everything that could be done via some basic bitwise shift operations, but lets face
 *	it, I was unable to make it work the right way. Apologies on my side.
 *
 *	Computation algorithm ripped off: https://en.wikipedia.org/wiki/Solicited-node_multicast_address 
 *	Input: in6_addr of target node (rest from address structure)
 *	Ouput: in6_addr of neighbor solicited-node multicast address
 */
in6_addr computeNSMCNodeAddress(in6_addr targetAddr)
{

	if (DEBUG)
	{
		std::cout << "======IP=====" << convertIPv6ToString(targetAddr) << std::endl;
	}

	// Prepare last 3 bytes of target address
	uint8_t targetLast24b[3];
	memcpy(targetLast24b, &targetAddr.s6_addr[13], 3);	

	// Prepare first 24 bytes of prefix address
	in6_addr prefixSNMAddress;
	convertStringToIPv6(IPV6_NS_PREFIX_OR_SOMETHING, &prefixSNMAddress);
	uint8_t prefixFirst104b[13];
	memcpy(prefixFirst104b, &prefixSNMAddress, 13);

	if (DEBUG)
	{
		std::cout << std::endl << "===DEBUG===" << std::endl;	
		std::cout << std::hex << (unsigned short) targetLast24b[0] << "." << std::hex << (unsigned short) targetLast24b[1] << "." << std::hex << (unsigned short) targetLast24b[2] << std::endl;	
		std::cout << (unsigned short) prefixFirst104b[0] << "." << (unsigned short) prefixFirst104b[1] <<  "." << (unsigned short) prefixFirst104b[2] <<  "." << (unsigned short) prefixFirst104b[3] << std::endl;
		std::cout << "===DEBUG===" << std::endl;			
	}

	// Merge prepared values together
	// BEHOLD MY MASTERPIECE!
	unsigned char tmp_s6_addr[16];
	tmp_s6_addr[0] = 	prefixFirst104b[0];
	tmp_s6_addr[1] = 	prefixFirst104b[1];
	tmp_s6_addr[2] = 	prefixFirst104b[2];
	tmp_s6_addr[3] = 	prefixFirst104b[3];
	tmp_s6_addr[4] = 	prefixFirst104b[4];
	tmp_s6_addr[5] = 	prefixFirst104b[5];
	tmp_s6_addr[6] = 	prefixFirst104b[6];
	tmp_s6_addr[7] = 	prefixFirst104b[7];
	tmp_s6_addr[8] = 	prefixFirst104b[8];
	tmp_s6_addr[9] = 	prefixFirst104b[9];
	tmp_s6_addr[10] = 	prefixFirst104b[10];
	tmp_s6_addr[11] = 	prefixFirst104b[11];
	tmp_s6_addr[12] = 	prefixFirst104b[12];
	tmp_s6_addr[13] = 	targetLast24b[0];
	tmp_s6_addr[14] = 	targetLast24b[1];
	tmp_s6_addr[15] =  	targetLast24b[2];				

	in6_addr nodeAddress;
	memcpy(&nodeAddress, &tmp_s6_addr, IPV6_LEN);

	return nodeAddress;		
}


/**
 * Scans for devices connected (via NDP)
 */
void discoverDevicesNDP()
{
	pid_t workerProc = fork();
	if (workerProc != CHILD_PROCESS)
	{
		// Now, parent is receiving packets
		ICMPv6Echo ping6PacketReply;

		int ndpResponseSocket = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
			if(ndpResponseSocket < 0)
			{
				std::cerr << "Unable to create NDP response socket. Better luck next time!" << std::endl;
				exit(1);
			}

		
		// IPv6 address of all nodes (the one we are going to ping)
		in6_addr myAddress;
		convertStringToIPv6(addresses.ipv6AddressLocal, &myAddress);

		// Prepare socket addr
		sockaddr_in6 socketAddress = prepareNDPSocketAddress(myAddress, P.interfaceName);


		int bindResult = bind(ndpResponseSocket, (struct sockaddr*) &socketAddress, sizeof(socketAddress));
		int errb = errno;
		if (bindResult < 0)
		{
			std::cerr << "Unable to bind socket for ping6 response! : " << errb << strerror(errb) << std::endl;
			exit(1);
		}

		// Receive responses
		while (true)
		{
			
			//std::cout << "Catching replies..." << std::endl;
			//std::cout << "Devices discovered. Proceeding to send solicitations." << std::endl; 

			struct timeval tv;
			tv.tv_sec = 1;
			tv.tv_usec = 0;

			if (setsockopt(ndpResponseSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
			{
				std::cerr << "Unable to set timeout for ndpResponseSocket." << std::endl;
				// But I guess that it is not a big deal
			}

			socklen_t forcedPointerLen = sizeof(socketAddress);
			if (recvfrom(ndpResponseSocket, &ping6PacketReply, sizeof(ping6PacketReply), 0, (struct sockaddr*)&socketAddress, &forcedPointerLen) <= 0)
			{
				//std::cerr << "0 bytes response, problems when receiving packet, or timeouted." << std::endl;
				break;
			}

			// Again focus only on PING replies
			if (ping6PacketReply.type != 129)
			{
				if (DEBUG)
					std::cout << "Received ICMPv6 packet, but was not of type Echo-Reply." << std::endl;

				continue;
			}


			// Don't forget that it also pings back with your IP
			if (addresses.ipv6AddressLocal != convertIPv6ToString(socketAddress.sin6_addr))	
			{
				discoveredPingIPv6.push_back(socketAddress.sin6_addr);
				std::cout << "IPv6 Device found: " << convertIPv6ToString(socketAddress.sin6_addr) << std::endl;
			}
		}

		
		waitpid(workerProc, NULL, 0);		// Wait for child that was sending ping requests
		close(ndpResponseSocket);

		// On discovered IPv6 send NS and read NA - parent should probably read (again), child should be sending - so we are not dealing with sharedmemory issues again
		pid_t solicitationSender = fork();

		int retry = 5;
		if (solicitationSender != CHILD_PROCESS)
		{
			// Socket for receiving adverts
			int ndpAdvertisementSocket = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
			if (ndpAdvertisementSocket < 0)
			{
				std::cerr << "Unable to create advertisement receiver socket." << std::endl;
			}

			in6_addr myIPv6Address;
			convertStringToIPv6(addresses.ipv6AddressLocal, &myIPv6Address);

			while(true)
			{
				// ADVERTISEMENT RECEIVAL
				NeighborAdvertisementPacket nap;
	
				// Prepare receiving socket address
				sockaddr_in6 socketAddressRecv =  prepareNDPSocketAddress(myIPv6Address, P.interfaceName);

				// And right away, receive something
				struct timeval tv;
				tv.tv_sec = 1;
				tv.tv_usec = 0;

				setsockopt(ndpAdvertisementSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
				socklen_t forcedPointerLen = sizeof(socketAddressRecv);
				if (recvfrom(ndpAdvertisementSocket, &nap, sizeof(nap), 0, (struct sockaddr*)&socketAddressRecv, &forcedPointerLen) <= 0)
				{
					std::cerr << "\tTimeout expired... retrying" << std::endl;

					if(!retry)
						break;

					retry--;	
					continue;
				}


				if (nap.head.nd_na_hdr.icmp6_type == 136)
				{
				
					std::cout << "Received NA reply from: " << convertIPv6ToString(nap.head.nd_na_target) << " with MAC ";
					printReadableMACAddress(nap.MAC);
					std::cout << std::endl;

					// Store discovered device
					Devices discovered;
					memcpy(&discovered.macAddress, nap.MAC, MAC_ADDR_LEN);
					discovered.ipv6AddressLL = convertIPv6ToString(nap.head.nd_na_target);
					discoveredDevices.push_back(discovered);

					// Reset retry counter and inform user
					std::cout << "Resetting retry counter, 5 retries remaining..." << std::endl;
					retry = 5;
				}				
			}

			waitpid(solicitationSender, NULL, 0);	// Wait for kid to do the sending
		}
		else
		{

			// For every discovered IPv6 send neighbor solicitation packet
			for (std::vector<in6_addr>::iterator it = discoveredPingIPv6.begin(); it != discoveredPingIPv6.end(); it++)
			{

				// Socket for sending solicitation requests
				int ndpSolicitationSocket = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
				if(ndpSolicitationSocket < 0)
				{
					std::cerr << "Unable to create solicitation socket." << std::endl;
				}

				int sockOptMaxHosts = 255;
				setsockopt(ndpSolicitationSocket, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &sockOptMaxHosts, sizeof(sockOptMaxHosts));

				// SOLICIT SEND-OUTS
				NeighborSolicitationPacket nsp;
				in6_addr targetAddr = *it;

				// For each addres compute its multicast solicit node address
				in6_addr NSMCNodeAddr  = computeNSMCNodeAddress(*it);

				// Socket address changes with every NS message to be send, so we have to change socket address appropriately in every iteration
				// Prepare socket address
				sockaddr_in6 socketAddress;
				socketAddress.sin6_family = AF_INET6;
				memcpy(&socketAddress.sin6_addr, &NSMCNodeAddr, IPV6_LEN);
				socketAddress.sin6_flowinfo = 0;
				socketAddress.sin6_port = 0;
				socketAddress.sin6_scope_id = 0; 



				// Prepare packet
				nsp.head.nd_ns_hdr.icmp6_type = 135;	//ND_NEIGHBOR_SOLICIT
				nsp.head.nd_ns_hdr.icmp6_code = 0;
				nsp.head.nd_ns_hdr.icmp6_cksum = htons ( 0 );
				nsp.head.nd_ns_reserved = htonl ( 0 );
				memcpy(&nsp.head.nd_ns_target, &targetAddr, IPV6_LEN);	
				nsp.type = NDP_ETHERNET_HWTYPE ;	// Not sure why, but with htons() it did not work
				nsp.length =  1;					// Not sure why, but with htons() it did not work
				memcpy(&nsp.MAC, &addresses.macAddressLocal, MAC_ADDR_LEN);
				
				// Send
				sendto(ndpSolicitationSocket, &nsp, sizeof (nsp), 0, (sockaddr*)&socketAddress, sizeof(socketAddress));

				int errbno = errno;
				if (!errbno)
				{
					std::cerr << "Failed to send neighbor solicitation" << errbno << std::endl;
				}


				if (DEBUG)
					std::cout << "=== Right about now, solicitation packet for " << convertIPv6ToString(*it) << std::endl;

				close(ndpSolicitationSocket);
			}

			exit(0);	// Kill the kid
		}
	}
	else	
	{
		// Child proces will now send discovery packets (pings)
		// Prepare IPv6 socket
		int ndpDiscoverySocket = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);		// Whole ping6 packet construction is heavily inspired by original ping6 implementation
			if (ndpDiscoverySocket < 0)
			{
				std::cerr << "Unable to open socket for NDP station discovery!" << std::endl;
				exit(1);
			}


		// IPv6 address of all nodes (the one we are going to ping)
		in6_addr allNodes;
		convertStringToIPv6(IPV6_ALLNODES, &allNodes);


		// Prepare IPv6 socket address
		sockaddr_in6 socketAddress = prepareNDPSocketAddress(allNodes, P.interfaceName);
	
		if (bind(ndpDiscoverySocket, (struct sockaddr*) &socketAddress, sizeof(socketAddress)) < 0)
		{
			std::cerr << "Unable to bind socket for NDP station discovery!" << std::endl;
			exit(1);
		}

		// Create ICMPv6 ping packet
		ICMPv6Echo ping6Packet;
		ping6Packet.type = 128; 								// TODO: Introduce proper constant for this
		ping6Packet.code = 0;	
		ping6Packet.identifier = htons ( 0 );					// As indirectly recommended by RFC ;)
		ping6Packet.sequence_number = htons ( 0 );				// As indirectly recommended by RFC ;)

		std::cout << "Discovering connected IPv6 devices..." << std::endl;
			sendto(ndpDiscoverySocket, &ping6Packet, sizeof(ping6Packet), 0, (struct sockaddr*) &socketAddress, sizeof(socketAddress));
			close(ndpDiscoverySocket);

	
		if (DEBUG)
		{
			char str[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &allNodes, str, INET6_ADDRSTRLEN);
		}
	
		exit(EXIT_SUCCESS);
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
		// Error
	}

	for (address = addressesStruct; address != NULL; address = address->ifa_next)
	{
		if (!address->ifa_addr)
			continue;

		// We are not interested in addresses belonging to other interfaces
		if (P.interfaceName.compare(address->ifa_name))
			continue;

		// TODO: Consider the possibility of interface having multiple IP addresses
		// IPv4 interface address
		if (address->ifa_addr->sa_family == AF_INET)
		{
			char strBuffer[INET_ADDRSTRLEN];

			// Only address & netmask
			addresses.netmask =	(struct sockaddr_in *) address->ifa_netmask;
			addresses.ipv4 	  = (struct sockaddr_in *) address->ifa_addr;

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
			
			memcpy(&addresses.ipv6AddressLocalRaw, (struct in6_addr*) address->ifa_addr, IPV6_LEN);

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
 *	Executes scanning of network segment and looks for active stations (via ARP)
 */
void discoverDevicesARP()
{

	std::cout << "Discovering connected IPv4 devices." << std::endl;

	// Calculate important network addresses	
	uint32_t subnet = ntohl(inet_addr(inet_ntoa(addresses.netmask->sin_addr)));
	uint32_t ip 	= ntohl(inet_addr(inet_ntoa(addresses.ipv4->sin_addr)));
	uint32_t networkAddress = (subnet & ip);
	uint32_t broadCastAddress = (networkAddress | (~subnet));


	ARPPacket arpDiscoveryPacket;

	pid_t workerProc = fork();
	if (workerProc != CHILD_PROCESS)
	{
		// Parent will receive packets that child process requested
		int arpResponseSocket = socket (AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
			if (arpResponseSocket < 0) { std::cerr << "Unable to open socket for ARP response receiving!" << std::endl; exit(1); }

		// Prepare local sockaddr_ll address
		struct sockaddr_ll socketAddress;
		prepareARPSocketAddress(&socketAddress, addresses.macAddressLocal);
		
		if (bind(arpResponseSocket, (sockaddr*) &socketAddress, sizeof(socketAddress)) < 0)
		{
			std::cerr << "Unable to bind socket for receiving ARP packets." << std::endl;
			exit(1);
		}

		// Take as long as it comes
		while(true)
		{

			// Prepare 2s timeout for recvfrom()
			struct timeval tv;
			tv.tv_sec = 2;
			tv.tv_usec = 0;

			if (setsockopt(arpResponseSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
			{
				std::cerr << "Unable to set timout for arpResponseSocket." << std::endl;
				// But I guess that it is not a big deal
			}


			if (recvfrom(arpResponseSocket, &arpDiscoveryPacket, sizeof(arpDiscoveryPacket), 0, NULL, NULL) <= 0)
			{
				std::cerr << "ARP scan finished." << std::endl;
				break;	// On exceeded timeout break the scan
			}

			if (arpDiscoveryPacket.operation != htons(ARP_OPERATION_REPLY))
			{
				std::cerr << "Packet that arrived was not ARP reply from requested station." << std::endl;
				continue;
			}


			// Inform user about discovered device and store it
			std::cout << "Discovered: ";
			printReadableMACAddress(arpDiscoveryPacket.sender_hw_addr);
			std::cout << " on IPv4 address: " << getReadableIPv4Address(arpDiscoveryPacket.sender_proto_addr) << std::endl;
					
			// Store discovered devices
			Devices discovered;
			memcpy(&discovered.macAddress, arpDiscoveryPacket.sender_hw_addr, MAC_ADDR_LEN);
			memcpy(&discovered.ipv4Address, arpDiscoveryPacket.sender_proto_addr, IPV4_LEN);
			
			discoveredDevices.push_back(discovered);
		}
		
		waitpid(workerProc, NULL, 0);	// Wait for child process to kill itself
	}
	else	
	{	
		// Create a socket and use it to send ARP request
		int arpDiscoverySocket = socket (AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
			if (arpDiscoverySocket < 0)
			{
				std::cerr << "Unable to open socket for ARP discovery!" << std::endl;
				exit(1);													
			}

		// For every IPv4 address within network segment, generate ARP request
		for (uint32_t i = (networkAddress+1); i < broadCastAddress; i++)
		{
			
			// Send ARP request to the address & accept reply (in other process|thread?)
			arpDiscoveryPacket.hw_type 			= htons ( ARP_ETHERNET_HWTYPE ) ;
			arpDiscoveryPacket.proto_type  		= htons ( ARP_IPV4_PROTOTYPE ) ;
			arpDiscoveryPacket.hw_addr_len 		= MAC_ADDR_LEN;
			arpDiscoveryPacket.proto_addr_len  	= IPV4_LEN;
			arpDiscoveryPacket.operation		= htons ( ARP_OPERATION_REQUEST );

			memcpy(&arpDiscoveryPacket.sender_hw_addr, &addresses.macAddressLocal, MAC_ADDR_LEN);	
			memcpy(&arpDiscoveryPacket.sender_proto_addr, &addresses.ipv4->sin_addr, IPV4_LEN);


			// Set proper byteorder for address 
			uint32_t tmpBOAddress = htonl ( i );

			// Set all target MAC address bytes to 0x00 (broadcast address)
			memset(&arpDiscoveryPacket.target_hw_addr, 0x00, MAC_ADDR_LEN);
			memcpy(&arpDiscoveryPacket.target_proto_addr, &tmpBOAddress, IPV4_LEN);


			struct sockaddr_ll socketAddress;
			socketAddress.sll_family   = AF_PACKET;										// Always AF_PACKET (manual)
			socketAddress.sll_protocol = htons ( ETH_P_ARP ); 							
			socketAddress.sll_ifindex  = if_nametoindex(P.interfaceName.c_str());
			socketAddress.sll_hatype   = 1; 											// It's ethennet hw type
			socketAddress.sll_pkttype  = PACKET_OTHERHOST;
			socketAddress.sll_halen	   = MAC_ADDR_LEN;
			memset(&socketAddress.sll_addr, 0xff, MAC_ADDR_LEN);

			if (bind(arpDiscoverySocket, (sockaddr*)&socketAddress, sizeof(socketAddress)) < 0)
			{
				std::cerr << "Unable to bind socket for ARP discovery." << std::endl;
			}

			if (sendto(arpDiscoverySocket, &arpDiscoveryPacket, sizeof(arpDiscoveryPacket), 0, (sockaddr*)&socketAddress, sizeof(socketAddress)) < 0)
			{
				std::cerr << "Error when sending out ARP packet." << std::endl;
			}
		}

		exit(EXIT_SUCCESS);		// Commit suicide successfully.
	}
}


/**
 *	Helper function that prepares sockaddr_ll basic values for socket
 */
void prepareARPSocketAddress(struct sockaddr_ll* socketAddress, uint8_t* address)
{
		socketAddress->sll_family = AF_PACKET;
		socketAddress->sll_protocol = htons (ETH_P_ARP);
		socketAddress->sll_ifindex = if_nametoindex(P.interfaceName.c_str());
		socketAddress->sll_hatype = 1;
		socketAddress->sll_pkttype = PACKET_OTHERHOST;
		socketAddress->sll_halen = MAC_ADDR_LEN;
		memcpy(&socketAddress->sll_addr, &address, MAC_ADDR_LEN);
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
 *	Helper function transforming common IPv4 representation to dotted notation
 */
std::string getReadableIPv4Address(uint8_t* address)
{
	char str[INET_ADDRSTRLEN];
	
	inet_ntop(AF_INET, (in_addr*) address, str, INET_ADDRSTRLEN);

	return std::string(str);
}


/**
 *  Helper function transforming common IPv4 representation to dotted notation 
 *	(different signature)
 */
std::string getReadableIPv4Address(uint32_t address)
{
	char str[INET_ADDRSTRLEN];
	uint32_t tmp = htonl(address);
	
	inet_ntop(AF_INET, &tmp, str, INET_ADDRSTRLEN);

	return std::string(str);
}


/**
 *  Helper fuinction converting common MAC address representation to something readable
 */
void printReadableMACAddress(uint8_t* MAC)
{
	printf("%02X:%02X:%02X:%02X:%02X:%02X", MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]);
}


/**
 *	Takes string representation of IPv6 address and stores its in6_addr 
 *	representation to allNodes parameter.
 */
void convertStringToIPv6(std::string ipv6, in6_addr* allNodes)
{
	inet_pton(AF_INET6, ipv6.c_str(), allNodes);
}


/**
 *	Helper function for converting IPv6 to something readable
 */
std::string convertIPv6ToString(in6_addr ipv6)
{
	char str[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, &ipv6, str, INET6_ADDRSTRLEN);

	return std::string(str);
}


/**
 * DEBUG FUNCTIONS
 */
void debug_showDiscoveredIPv6()
{
	for (std::vector<in6_addr>::iterator it = discoveredPingIPv6.begin(); it != discoveredPingIPv6.end(); it++)
	{
		std::cout << "Discovered IPv6: " << convertIPv6ToString(*it) << std::endl;
	}
}

void debug_showDiscoveredDevices()
{
	for (std::vector<Devices>::iterator it = discoveredDevices.begin(); it != discoveredDevices.end(); it++)
	{
		std::cout << "Discovered: ";
		printReadableMACAddress(it->macAddress);
		std::cout << " on IPv4 address: " << getReadableIPv4Address(it->ipv4Address) << std::endl;
	}
}