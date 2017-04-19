#include <iostream>



#include <stdio.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>


#define EXIT_SUCCESS 0
#define DEBUG 1

void extractAddressesForInterface();
void extractAllInterfaceAddresses();
void discoverDevicesARP();
void discoverDevicesNDP();


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

	// Initiate NDP scanning (if applicable) - IPv6
	discoverDevicesNDP();

	return EXIT_SUCCESS;

}

void extractAddressesForInterface()
{
	struct ifaddrs* addressesStruct = NULL;
	struct ifaddrs* address = NULL;
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
			// TODO: IPv6 - the same thing under
			char strBuffer[INET6_ADDRSTRLEN];

			tmpAddrPtr = &((struct sockaddr_in6 *) address->ifa_addr)->sin6_addr;
			inet_ntop(AF_INET6, tmpAddrPtr, strBuffer, INET6_ADDRSTRLEN);

			addresses.ipv6AddressLocal = strBuffer;

			if (DEBUG)
				printf("Saved interface IPv6 address %s\n", addresses.ipv6AddressLocal.c_str());
		}
	}

	freeifaddrs(addressesStruct);
}



void discoverDevicesARP()
{
	std::cout << "Scanning network for devices via ARP" << std::endl;

	uint32_t subnet = ntohl(inet_addr(inet_ntoa(addresses.netmask->sin_addr)));
	uint32_t ip 	= ntohl(inet_addr(inet_ntoa(addresses.ipv4->sin_addr)));

	uint32_t networkAddress = (subnet & ip);
	uint32_t broadCastAddress = (networkAddress | (~subnet));


	std::cout << "Network address: " << networkAddress << std::endl;
	std::cout << "Broadcast address: " << broadCastAddress << std::endl;

	for (uint32_t i = (networkAddress+1); i < broadCastAddress; i++)
	{


		uint32_t tmp = htonl(i);

		char str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &tmp, str, INET_ADDRSTRLEN);

		std::cout << "I found address: " << str << std::endl;
	}

	



}

void discoverDevicesNDP()
{
	std::cout << "Scanning network for devices via ARP" << std::endl;
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
