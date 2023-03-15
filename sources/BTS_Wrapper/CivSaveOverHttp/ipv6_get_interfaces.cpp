#include "stdafx.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sstream>

// Code copied from https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>

#include <ws2ipdef.h>

#include "CivSaveOverHttp.h"

#ifdef WITH_IPv6

// Link with Iphlpapi.lib
#pragma comment(lib, "IPHLPAPI.lib")

#define WORKING_BUFFER_SIZE 15000
#define MAX_TRIES 3

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

/* Note: could also use malloc() and free() */

char* __cdecl get_ip6_for_ip4(const char *_ip4, bool reverse_lookup)
{
  const std::string ip4(_ip4);
  char *ret = NULL;

  /* Declare and initialize variables */

  DWORD dwSize = 0;
  DWORD dwRetVal = 0;

  unsigned int i = 0;

  // Set the flags to pass to GetAdaptersAddresses
  ULONG flags = GAA_FLAG_INCLUDE_PREFIX 
    | GAA_FLAG_SKIP_MULTICAST //| GAA_FLAG_SKIP_ANYCAST 
    | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME;

  // default to unspecified address family (both)
  ULONG family = AF_UNSPEC;

  LPVOID lpMsgBuf = NULL;

  PIP_ADAPTER_ADDRESSES pAddresses = NULL;
  ULONG outBufLen = 0;
  ULONG Iterations = 0;

  PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
  PIP_ADAPTER_UNICAST_ADDRESS pUnicast = NULL;
  PIP_ADAPTER_ANYCAST_ADDRESS pAnycast = NULL;
  PIP_ADAPTER_MULTICAST_ADDRESS pMulticast = NULL;
  IP_ADAPTER_DNS_SERVER_ADDRESS *pDnServer = NULL;
  IP_ADAPTER_PREFIX *pPrefix = NULL;

  PIP_ADAPTER_ADDRESSES pMatchingAddresses = NULL;
  PIP_ADAPTER_UNICAST_ADDRESS pBestUnicast = NULL;

  // Allocate a 15 KB buffer to start with.
  outBufLen = WORKING_BUFFER_SIZE;

  do {

    pAddresses = (IP_ADAPTER_ADDRESSES *) MALLOC(outBufLen);
    if (pAddresses == NULL) {
      LOGPRINT("(IP6) Memory allocation failed for IP_ADAPTER_ADDRESSES struct");
      return ret;
    }

    dwRetVal =
      GetAdaptersAddresses(family, flags, NULL, pAddresses, &outBufLen);

    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
      FREE(pAddresses);
      pAddresses = NULL;
    } else {
      break;
    }

    Iterations++;

  } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (Iterations < MAX_TRIES));

  if (dwRetVal == NO_ERROR) {
    // If successful, output some information from the data we received
    pCurrAddresses = pAddresses;
    while (pCurrAddresses) {
#if 0
      LOGPRINT("\n\n(IP6) \tLength of the IP_ADAPTER_ADDRESS struct: " << pCurrAddresses->Length);
      LOGPRINT("(IP6) \tIfIndex (IPv4 interface): " << pCurrAddresses->IfIndex);
      LOGPRINT("(IP6) \tAdapter name: " << pCurrAddresses->AdapterName);

      pUnicast = pCurrAddresses->FirstUnicastAddress;
      if (pUnicast != NULL) {
        for (i = 0; pUnicast != NULL; i++)
          pUnicast = pUnicast->Next;
        LOGPRINT("(IP6) \tNumber of Unicast Addresses: " << i);
      } else {
        LOGPRINT("(IP6) \tNo Unicast Addresses");
      }

      pAnycast = pCurrAddresses->FirstAnycastAddress;
      if (pAnycast) {
        for (i = 0; pAnycast != NULL; i++)
          pAnycast = pAnycast->Next;
        LOGPRINT("(IP6) \tNumber of Anycast Addresses: " << i);
      } else {
        LOGPRINT("(IP6) \tNo Anycast Addresses");
      }

      pMulticast = pCurrAddresses->FirstMulticastAddress;
      if (pMulticast) {
        for (i = 0; pMulticast != NULL; i++)
          pMulticast = pMulticast->Next;
        LOGPRINT("(IP6) \tNumber of Multicast Addresses: " << i);
      } else {
        LOGPRINT("(IP6) \tNo Multicast Addresses");
      }

      pDnServer = pCurrAddresses->FirstDnsServerAddress;
      if (pDnServer) {
        for (i = 0; pDnServer != NULL; i++)
          pDnServer = pDnServer->Next;
        LOGPRINT("(IP6) \tNumber of DNS Server Addresses: " << i);
      } else {
        LOGPRINT("(IP6) \tNo DNS Server Addresses");
      }

      LOGPRINT("(IP6) \tDNS Suffix: " << pCurrAddresses->DnsSuffix);
      LOGPRINT("(IP6) \tDescription: " << pCurrAddresses->Description);
      LOGPRINT("(IP6) \tFriendly name: " << pCurrAddresses->FriendlyName);

      if (pCurrAddresses->PhysicalAddressLength != 0) {
        LOGPRINT0("(IP6) \tPhysical address: ");
        for (i = 0; i < (int) pCurrAddresses->PhysicalAddressLength; i++) {
          if (i == (pCurrAddresses->PhysicalAddressLength - 1)) {
            LOGPRINT( std::hex << (int) pCurrAddresses->PhysicalAddress[i]);
          }else{
            LOGPRINT0( std::hex << (int) pCurrAddresses->PhysicalAddress[i]);
          }
        }
      }
      LOGPRINT("(IP6) \tFlags: " << pCurrAddresses->Flags);
      LOGPRINT("(IP6) \tMtu: " << pCurrAddresses->Mtu);
      LOGPRINT("(IP6) \tIfType: " << pCurrAddresses->IfType);
      LOGPRINT("(IP6) \tOperStatus: " << pCurrAddresses->OperStatus);
      LOGPRINT("(IP6) \tIpv6IfIndex (IPv6 interface): " << pCurrAddresses->Ipv6IfIndex);
      LOGPRINT0("(IP6) \tZoneIndices (hex): ");
      for (i = 0; i < 16; i++) {
        LOGPRINT0( std::hex << pCurrAddresses->ZoneIndices[i]);
      }
      LOGPRINT("");

      LOGPRINT("(IP6) \tTransmit link speed: " << pCurrAddresses->TransmitLinkSpeed);
      LOGPRINT("(IP6) \tReceive link speed: " << pCurrAddresses->ReceiveLinkSpeed);

      pPrefix = pCurrAddresses->FirstPrefix;
      if (pPrefix) {
        for (i = 0; pPrefix != NULL; i++)
          pPrefix = pPrefix->Next;
        LOGPRINT0("\tNumber of IP Adapter Prefix entries: " << i);
      } else {
        LOGPRINT0("\tNumber of IP Adapter Prefix entries: 0");
      }
      LOGPRINT("");
#endif

      // Searching
      if (pCurrAddresses->IfIndex != 0 ) { // 0 means no ip4 address on this interface

        pUnicast = pCurrAddresses->FirstUnicastAddress;
        while( pUnicast != NULL ) {
          // Compare current unicast address with given ipv4
          if (pUnicast->Address.lpSockaddr != NULL
              && pUnicast->Address.lpSockaddr->sa_family == AF_INET) {

            sockaddr_in* foo = (sockaddr_in*)pUnicast->Address.lpSockaddr;
            std::stringstream _tmp;
            _tmp << std::dec << (int)(foo->sin_addr.S_un.S_un_b.s_b1) << "."
              << std::dec << (int)(foo->sin_addr.S_un.S_un_b.s_b2) << "."
              << std::dec << (int)(foo->sin_addr.S_un.S_un_b.s_b3) << "."
              << std::dec << (int)(foo->sin_addr.S_un.S_un_b.s_b4);

            std::string ip4B = _tmp.str();
            LOGPRINT("(IP6) Compare    " << ip4B << " vs " << ip4);

            if( 0 == ip4B.compare(ip4)) {
              pMatchingAddresses = pCurrAddresses;
              pCurrAddresses = NULL;
              break;
            }
          }

          pUnicast = pUnicast->Next;
        }
      }

      if( pCurrAddresses) {
        pCurrAddresses = pCurrAddresses->Next;
      }
    } // while (pCurrAddresses) end

    /* Search best global IPv6 address on same interface as IPv4 address.
     * Local link addresses will be discarded and
     * for 'PREFER_TEMP_IPv6 == 1' temporary addresses will be preferred.
     *
     * Preferring random interfaces maybe collides with long Civ4 MP sessions?!
     */
    if (pMatchingAddresses != NULL) {
      pUnicast = pMatchingAddresses->FirstUnicastAddress;
      pBestUnicast = NULL;
      /* If PREFER_TEMP_IPv6 is 1 this flag will set for IpSuffixOriginRandom address
       * and otherwise for all other non-local interfaces
       */
      bool preferred_suffix_found(false);
      unsigned long max_preferred_lifetime(0);
      while (pUnicast != NULL) {
        if (pUnicast->Address.lpSockaddr != NULL
            && pUnicast->Address.lpSockaddr->sa_family == AF_INET6)
        {

          sockaddr_in6* bar = (sockaddr_in6*)pUnicast->Address.lpSockaddr;

          // Other variant to get the bytes..
          //char a[INET6_ADDRSTRLEN] = {};
          // if (inet_ntop(AF_INET6, &(si->sin6_addr), a, sizeof(a))) { ... }

          /* Expected IPv6 name   AABB:CCDD:...
           * Wrong byte order     BBAA bar->sin6_addr.u.Word[0]
           * Wrong for AABB=0101  AABB bar->sin6_addr.u.Byte[0] , bar->sin6_addr.u.Byte[1]
           * Ok                   AABB ((bar->sin6_addr.u.Byte[0] << 8) | bar->sin6_addr.u.Byte[1])
           */
          std::stringstream _tmp;
          _tmp 
            << "[" << std::hex << (int)((bar->sin6_addr.u.Byte[ 0] << 8) | bar->sin6_addr.u.Byte[ 1])
            << ":" << std::hex << (int)((bar->sin6_addr.u.Byte[ 2] << 8) | bar->sin6_addr.u.Byte[ 3])
            << ":" << std::hex << (int)((bar->sin6_addr.u.Byte[ 4] << 8) | bar->sin6_addr.u.Byte[ 5])
            << ":" << std::hex << (int)((bar->sin6_addr.u.Byte[ 6] << 8) | bar->sin6_addr.u.Byte[ 7])
            << ":" << std::hex << (int)((bar->sin6_addr.u.Byte[ 8] << 8) | bar->sin6_addr.u.Byte[ 9])
            << ":" << std::hex << (int)((bar->sin6_addr.u.Byte[10] << 8) | bar->sin6_addr.u.Byte[11])
            << ":" << std::hex << (int)((bar->sin6_addr.u.Byte[12] << 8) | bar->sin6_addr.u.Byte[13])
            << ":" << std::hex << (int)((bar->sin6_addr.u.Byte[14] << 8) | bar->sin6_addr.u.Byte[15])
            << "]";
          LOGPRINT("(IP6) " << _tmp.str());

          if ((bar->sin6_addr.u.Word[0] & 0x80FE) == 0x80FE) { // LittleEndian/Flipped byte order!
            pUnicast = pUnicast->Next;
            continue; // link local address not useful for us
          }
          if (
#if PREFER_TEMP_IPv6
              pUnicast->SuffixOrigin == IpSuffixOriginRandom
#else
              pUnicast->SuffixOrigin != IpSuffixOriginRandom
#endif
             ) { // Bad auto-indetion if '{' is inside of #ifdefs 
#if PREFER_TEMP_IPv6
            LOGPRINT("(IP6) Found temporary address");
#else
            LOGPRINT("(IP6) Found global static address");
#endif
            if (!preferred_suffix_found) {
              max_preferred_lifetime = 0;
            }
            if (max_preferred_lifetime < pUnicast->PreferredLifetime) {
              max_preferred_lifetime = pUnicast->PreferredLifetime;
              pBestUnicast = pUnicast;
            }
            preferred_suffix_found = true;
          }else{
            if (preferred_suffix_found) {
              // skip this global address because we've found already a better one
              pUnicast = pUnicast->Next;
              continue;
            }
            if (max_preferred_lifetime < pUnicast->PreferredLifetime) {
              max_preferred_lifetime = pUnicast->PreferredLifetime;
              pBestUnicast = pUnicast;
            }
          }
        }

        pUnicast = pUnicast->Next;
      } // Ends while (pUnicast != NULL) 
    }

    if (pBestUnicast) {
      sockaddr_in6* bar = (sockaddr_in6*)pBestUnicast->Address.lpSockaddr;

      std::stringstream _tmp;
      _tmp 
        << "[" << std::hex << (int)((bar->sin6_addr.u.Byte[ 0] << 8) | bar->sin6_addr.u.Byte[ 1])
        << ":" << std::hex << (int)((bar->sin6_addr.u.Byte[ 2] << 8) | bar->sin6_addr.u.Byte[ 3])
        << ":" << std::hex << (int)((bar->sin6_addr.u.Byte[ 4] << 8) | bar->sin6_addr.u.Byte[ 5])
        << ":" << std::hex << (int)((bar->sin6_addr.u.Byte[ 6] << 8) | bar->sin6_addr.u.Byte[ 7])
        << ":" << std::hex << (int)((bar->sin6_addr.u.Byte[ 8] << 8) | bar->sin6_addr.u.Byte[ 9])
        << ":" << std::hex << (int)((bar->sin6_addr.u.Byte[10] << 8) | bar->sin6_addr.u.Byte[11])
        << ":" << std::hex << (int)((bar->sin6_addr.u.Byte[12] << 8) | bar->sin6_addr.u.Byte[13])
        << ":" << std::hex << (int)((bar->sin6_addr.u.Byte[14] << 8) | bar->sin6_addr.u.Byte[15])
        << "]";
      LOGPRINT("(IP6) best IPv6 found: " << _tmp.str());
      ret = _strdup(_tmp.str().c_str());
    }


  } else {
    LOGPRINT("(IP6) Call to GetAdaptersAddresses failed with error: " << dwRetVal);
    if (dwRetVal == ERROR_NO_DATA) {
      LOGPRINT("(IP6) \tNo addresses were found for the requested parameters");
    } else {
      if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, 
            NULL, dwRetVal, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),   
            // Default language
            (LPTSTR) & lpMsgBuf, 0, NULL)) {
        LOGPRINT("(IP6) \tError: " << lpMsgBuf);
        LocalFree(lpMsgBuf);
      }
    }
  }
  //LOGPRINT("(IP6) end");

  if (pAddresses) {
    FREE(pAddresses);
  }

  return ret;
}

#endif
