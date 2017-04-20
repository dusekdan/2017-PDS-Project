#include <iostream>
#include <vector>


#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "pds-scanner.h"

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <net/ethernet.h>

#include <unistd.h>
#include <sys/wait.h>
#include <sys/time.h>


#define EXIT_SUCCESS 0
#define DEBUG 1

void extractAddressesForInterface();
void extractAllInterfaceAddresses();
void discoverDevicesARP();
void discoverDevicesNDP();

std::string getReadableIPv4Address(uint32_t address);
std::string getReadableIPv4Address(uint8_t* address);
void printReadableMACAddress(uint8_t* MAC);

void debug_showDiscoveredDevices();

struct Parameters
{
	std::string interfaceName;
	std::string outputFileName;
};
struct Parameters P;

struct Network
{
	std::string ipv4AddressLocal;
	uint32_t	ipv4Local;
	uint32_t	ipv4NetworkMask;


	struct sockaddr_in* netmask;
	struct sockaddr_in* ipv4;

	uint8_t		macAddressLocal[MAC_ADDR_LEN];

	std::string ipv6AddressLocal;
	//struct in_addr ipv4;
};
struct Network addresses;



int main(int argc, char **argv)
{
	// Process parameters


	// TODO: Remove hardcoded input variables
	P.interfaceName = "eth1";
	P.outputFileName = "ScanResults.xml";


	// TODO: Think about design point of view (global variable, really?)
	// Extract required information from provided interface and store it to global variable/proper structure
	extractAddressesForInterface();


	// How to print dot notation of IPv4 address: 				inet_ntoa(addresses.ipv4->sin_addr)
	// Convert this to numeric representation					ntohl(inet_addr(inet_ntoa(addresses.ipv4->sin_addr)))
	// - There is ntohl because we work with 32bit numbers and we have to ensure right byte order

	// Test whether values are loaded properly
	// std::cout << "IPv4: "  << std::hex << ntohl(inet_addr(inet_ntoa(addresses.ipv4->sin_addr))) << std::endl;
	// std::cout << "Maska: " << std::hex << ntohl(inet_addr(inet_ntoa(addresses.netmask->sin_addr))) << std::endl;

	// Initiate ARP scanning (if applicable) - IPv4
	discoverDevicesARP();

	if (DEBUG)
		debug_showDiscoveredDevices();

	// Initiate NDP scanning (if applicable) - IPv6
	discoverDevicesNDP();

	return EXIT_SUCCESS;

}

void debug_showDiscoveredDevices()
{
	for (std::vector<Devices>::iterator it = discoveredDevices.begin(); it != discoveredDevices.end(); it++)
	{
		std::cout << "Discovered: ";
		printReadableMACAddress(it->macAddress);
		std::cout << "on IPv4 address: " << getReadableIPv4Address(it->ipv4Address) << std::endl;
	}
}

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

			//memcpy(&addresses.ipv4, address->ifa_addr, IPV4_LEN);

			tmpAddrPtr = &((struct sockaddr_in *) address->ifa_addr)->sin_addr;
			inet_ntop(AF_INET, tmpAddrPtr, strBuffer, INET_ADDRSTRLEN);

			addresses.ipv4AddressLocal = strBuffer;

			if (DEBUG)
				printf("Saved interface IPv4 address %s\n", addresses.ipv4AddressLocal.c_str());
		}
		else if (address->ifa_addr->sa_family == AF_INET6)
		{
			// TODO: IPv6 - the same thing under
			char strBuffer[INET6_ADDRSTRLEN];

			tmpAddrPtr = &((struct sockaddr_in6 *) address->ifa_addr)->sin6_addr;
			inet_ntop(AF_INET6, tmpAddrPtr, strBuffer, INET6_ADDRSTRLEN);

			addresses.ipv6AddressLocal = strBuffer;

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
				uint8_t* mac = (uint8_t*) req.ifr_ifru.ifru_hwaddr.sa_data; 	// WARNING: Risc of segfault?
				memcpy(&addresses.macAddressLocal, mac, MAC_ADDR_LEN);


				if (DEBUG)
					std::cout << "MAC Address for Interface " << P.interfaceName << ": ";
					printReadableMACAddress(addresses.macAddressLocal);
					std::cout << std::endl;

			}
		}
	}

	freeifaddrs(addressesStruct);
}



void discoverDevicesARP()
{
	uint32_t subnet = ntohl(inet_addr(inet_ntoa(addresses.netmask->sin_addr)));
	uint32_t ip 	= ntohl(inet_addr(inet_ntoa(addresses.ipv4->sin_addr)));

	uint32_t networkAddress = (subnet & ip);
	uint32_t broadCastAddress = (networkAddress | (~subnet));


	std::cout << "Network address: " << networkAddress << std::endl;
	std::cout << "Broadcast address: " << broadCastAddress << std::endl;


	ARPPacket arpDiscoveryPacket;

	//std::vector<std::string> niceIPs;
	//std::vector<uint32_t> IPsInRange;

	pid_t workerProc = fork();
	
	if (workerProc == CHILD_PROCESS)
	{
		// CHild should start receiving
		std::cout << "I AM A CHILD AND I AM WAITING FOR SOMETING" << std::endl;

		int arpResponseSocket = socket (AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
		if (arpResponseSocket < 0)
		{
			std::cerr << "Unable to open socket  for ARP response receiving!" << std::endl;
			exit(1);
		}

		// Prepare local sockaddr_ll address
		struct sockaddr_ll socketAddress;
		socketAddress.sll_family = AF_PACKET;
		socketAddress.sll_protocol = htons (ETH_P_ARP);
		socketAddress.sll_ifindex = if_nametoindex(P.interfaceName.c_str());
		socketAddress.sll_hatype = 1;
		socketAddress.sll_pkttype = PACKET_OTHERHOST;
		socketAddress.sll_halen = MAC_ADDR_LEN;
		memcpy(&socketAddress.sll_addr, &addresses.macAddressLocal, MAC_ADDR_LEN);

		if (bind(arpResponseSocket, (sockaddr*) &socketAddress, sizeof(socketAddress)) < 0)
		{
			std::cerr << "Unable to bind socket for receiving ARP packets." << std::endl;
			exit(1);
		}

		// We dont know when the stuff start coming
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
				std::cerr << "0 bytes response, problems when receiving packet, or timeouted." << std::endl;
				break;
			}

			if (arpDiscoveryPacket.operation != htons(ARP_OPERATION_REPLY))
			{
				std::cerr << "Packet that arrived was not ARP reply from requested station." << std::endl;
				continue;
			}

			// We know we have something, so we show it:
			std::cout << "Discovered device on MAC:";

			printReadableMACAddress( arpDiscoveryPacket.sender_hw_addr );



			std::cout << " on IP:" << getReadableIPv4Address(arpDiscoveryPacket.sender_proto_addr) << "." << std::endl;
			
			// I should probably store it somewhere too
			Devices discovered;
			memcpy(&discovered.macAddress, arpDiscoveryPacket.sender_hw_addr, MAC_ADDR_LEN);
			memcpy(&discovered.ipv4Address, arpDiscoveryPacket.sender_proto_addr, IPV4_LEN);
			
			discoveredDevices.push_back(discovered);
			// And figure out how to end on time

			
		}

		// Make sure child process does not continue any further
		exit(EXIT_SUCCESS);
	}
	else	// Parent sends ARP requests
	{	
		// Create a socket and use it to send request
		int arpDiscoverySocket = socket (AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
			if (arpDiscoverySocket < 0)
			{
				std::cerr << "Unable to open socket for ARP discovery!" << std::endl;
				exit(1);													// TODO: Reconsider exit codes
			}


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
			socketAddress.sll_family   = AF_PACKET;	// Always AF_PACKET (manual)
			socketAddress.sll_protocol = htons ( ETH_P_ARP ); // To see all packets, ETH_P_IP would see only incoming (not necesary here, but will be later in)
			socketAddress.sll_ifindex  = if_nametoindex(P.interfaceName.c_str());
			socketAddress.sll_hatype   = 1; // figure this out, it should be explained on arp(7p) man page
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
			else
			{
				//std::cout << "Sending out packet, now!" << std::endl;
			}


			//std::cout << htons (i) << std::endl;


			//niceIPs.push_back(getReadableIPv4Address(i));
			//IPsInRange.push_back(i);	// TODO: Think about using htonl() here.
			
		}

	

		// TODO: Use this to print out possible report for errorneous child termination
		waitpid(workerProc, NULL, 0);
	}

	

	// Printing contents of niceIPs
	/*for (std::vector<std::string>::iterator it = niceIPs.begin(); it != niceIPs.end(); it++)
	{
		std::cout << "IP address: " << *it << std::endl;
	}*/



	



}

std::string getReadableIPv4Address(uint8_t* address)
{
	char str[INET_ADDRSTRLEN];
	
	inet_ntop(AF_INET, (in_addr*) address, str, INET_ADDRSTRLEN);

	return std::string(str);
}


std::string getReadableIPv4Address(uint32_t address)
{
	char str[INET_ADDRSTRLEN];
	uint32_t tmp = htonl(address);
	
	inet_ntop(AF_INET, &tmp, str, INET_ADDRSTRLEN);

	return std::string(str);
}

void printReadableMACAddress(uint8_t* MAC)
{
	printf("%02X:%02X:%02X:%02X:%02X:%02X", MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]);
}

void discoverDevicesNDP()
{
	std::cout << "Scanning network for devices via NDP" << std::endl;
}























/*
	// UNUSED CODE, PROOFS OF CONCEPT, ETC.

 
void extractAllInterfaceAddresses()
{
	struct ifaddrs* fullStructure = NULL;
	struct ifaddrs* address = NULL;
	void * tmpAddrPtr = NULL;

	if (getifaddrs(&fullStructure) != 0)
	{
		std::cerr << "Function getifaddrs() failed. Sorry about that." << std::endl;
	}

	for (address = fullStructure; address != NULL; address = address->ifa_next)
	{
		if (!address->ifa_addr)
			continue;

		if (address->ifa_addr->sa_family == AF_INET)
		{
			tmpAddrPtr = &((struct sockaddr_in *) address->ifa_addr)->sin_addr;
			char addressBuffer[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
			addresses.ipv4AddressLocal = addressBuffer;
			printf("IP Address %s\n", addresses.ipv4AddressLocal.c_str());
		}
		else if (address->ifa_addr->sa_family == AF_INET6)
		{
			tmpAddrPtr = &((struct sockaddr_in6 *) address->ifa_addr)->sin6_addr;
			char addressBuffer[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, tmpAddrPtr, addressBuffer, INET6_ADDRSTRLEN);
			printf("%s IP Address %s\n", address->ifa_name, addressBuffer);
		}
	}

	if (fullStructure!=NULL)
		freeifaddrs(fullStructure);
}

*/
