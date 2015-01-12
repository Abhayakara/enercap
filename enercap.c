/* enercap.c
 *
 * Enercap is a home energy monitor capture program.
 * 
 * Copyright (C) 2015  Edward Lemon III
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Enercap is a home energy monitor and its server to capture the
 * monitoring data so that it can be crunched locally without
 * disabling the upstream service.
 */

#define __APPLE_USE_RFC_3542 1 /* bogus */
#define _GNU_SOURCE 1 /* also bogus. */

#include <sys/errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <syslog.h>
#include <time.h>
//#include <netpacket/packet.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

#include <pcap/pcap.h>

typedef union {
  struct sockaddr sa;
  struct sockaddr_in in;
  struct sockaddr_in6 in6;
} address_t;

typedef struct {
  const char *name;
  int total;
  int fragmented;
  int nopayload;
  int shorthdr;
  int toolong;
  int tooshort;
  int unknown_type;
  int udp;
  int tcp;
} stats_t;


static void
tcpin(address_t *src, address_t *dest, struct tcphdr *tcp, stats_t *stats,
      const u_char *bytes, int inp, int inlen)
{
}

static void
one_packet (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
  size_t inlen = h->caplen;
  int cidp;
  int inp = 0; // skip ethernet header
  struct ether_header ether;
  int transport_type;
  address_t src, dest;
  int paylen;
  stats_t *stats = (stats_t *)user;

  stats->total++;
  memset(&src, 0, sizeof src);
  memset(&dest, 0, sizeof dest);

  memcpy(&ether, &bytes[inp], sizeof ether);
  inp += sizeof ether;

  if (ntohs(ether.ether_type) == ETH_P_IP)
    {
      struct iphdr ip;

      // Copy out the IP header if we captured enough bytes.
      if (sizeof ip > inlen - inp)
	{
	  stats->tooshort++;
	  return;
	}
      memcpy(&ip, &bytes[inp], sizeof ip);

      // If the header length is less than five, it's invalid.
      if (ip.ihl * 4 < sizeof ip)
	{
	  stats->shorthdr++;
	  return;
	}

      // XXX fixme: look for IPsec header
      // We do not attempt to parse the optional headers, so if IPsec
      // encryption is in use, what follows will be garbled.
      // I haven't coded this because I know the emonitor doesn't use IPsec.
      inp += ip.ihl * 4;

      // Get the length of the datagram not including the header. 
      paylen = ntohs(ip.tot_len) - ip.ihl * 4;

      // The packet is invalid if the payload length is more than we captured.
      if (paylen > inlen - inp)
	{
	  stats->toolong++;
	  return;
	}

      // We don't handle fragmentation.
      if (ntohs(ip.frag_off) & 0x1fff != 0 || ntohs(ip.frag_off) & 0x2000)
	{
	  stats->fragmented++;
	  return;
	}

      // Get the transport type.
      transport_type = ip.protocol;

      // Copy out the source and destination IP addresses.
      src.sa.sa_family = dest.sa.sa_family = AF_INET;
      memcpy(&src.in.sin_addr, &ip.saddr, sizeof ip.saddr);
      memcpy(&dest.in.sin_addr, &ip.daddr, sizeof ip.daddr);
    }
  else if (ntohs(ether.ether_type) == ETH_P_IPV6)
    {
      struct ip6_hdr ip;
      int nxthdr;

      // If there's room for an IPv6 header, copy it.
      if (inlen - inp < sizeof ip)
	{
	  stats->tooshort++;
	  return;
	}
      memcpy(&ip, &bytes[inp], sizeof ip);

      // IP header length is fixed; extension headers follow.
      inp += sizeof ip;

      src.sa.sa_family = dest.sa.sa_family = AF_INET6;
      memcpy(&src.in6.sin6_addr, &ip.ip6_src, sizeof ip.ip6_src);
      memcpy(&dest.in6.sin6_addr, &ip.ip6_dst, sizeof ip.ip6_dst);

      // process the headers...
      nxthdr = ip.ip6_nxt;
      do
	{
	  switch(nxthdr)
	    {
	      // No next header (drop)
	    case 59:
	      stats->nopayload++;
	      return;

	      // Fragment (not supported)
	    case 44:
	      stats->fragmented++;
	      return;

	      // TCP header
	    case 6:
	      transport_type = IPPROTO_TCP;
	      nxthdr = 59;
	      break;

	      // UDP header
	    case 17:
	      transport_type = IPPROTO_UDP;
	      nxthdr = 59;
	      break;

	    case 0: // hop-by-hop
	    case 43: // routing header
	    case 60: // destination options header
	      // If there's no room for a next header tag or length, drop.
	      if (inp + 2 == inlen)
		{
		  stats->tooshort++;
		  return;
		}

	      // Get the next header type
	      nxthdr = bytes[inp];

	      // Skip over the header.
	      inp += 1 + bytes[inp + 1];
	      if (inp > inlen)
		{
		  stats->tooshort++;
		  return;
		}
	      break;

	    default:
	      stats->unknown_type++;
	      break;
	    }
	} while (nxthdr != 59);
      // At this point we have a valid transport type, and inp is the
      // index into bytes at which the transport header begins.
    }

  if (transport_type == IPPROTO_TCP)
    {
      stats->tcp++;
      struct tcphdr tcp;
      if (inlen - inp < sizeof tcp)
	{
	  stats->tooshort++;
	  return;
	}
      memcpy(&tcp, &bytes[inp], sizeof tcp);
      inp -= sizeof tcp;

      if (src.sa.sa_family == AF_INET)
	{
	  src.in.sin_port = tcp.th_sport;
	  dest.in.sin_port = tcp.th_dport;
	}
      else if (src.sa.sa_family == AF_INET6)
	{
	  src.in6.sin6_port = tcp.th_sport;
	  dest.in6.sin6_port = tcp.th_dport;
	}
      else
	abort();	// impossible if earlier logic is correct.

      // Process the TCP packet.
      tcpin(&src, &dest, &tcp, stats, bytes, inp, inlen);
    }
  else if (transport_type == IPPROTO_UDP)
    stats->udp++;

  // process the packet
  return;
}

int
main(int argc, char **argv)
{
  int i;
  pcap_t *p;
  char errbuf[PCAP_ERRBUF_SIZE];
  
  if (argc == 1)
    {
      fprintf(stderr,
	      "usage: ddt pcap-trace [pcap-trace [ ... [pcap-trace]]]\n");
      exit(1);
    }

  for (i = 1; i < argc; i++)
    {  
      stats_t stats;
      p = pcap_open_offline(argv[i], errbuf);
      if (!p)
	{
	  fprintf(stderr, "%s: %s\n", argv[i], errbuf);
	  exit(1);
	}
      memset(&stats, 0, sizeof stats);
      stats.name = argv[i];
      pcap_loop(p, 0, one_packet, (u_char *)&stats);
      pcap_close(p);
      printf("stats for %s\n", argv[i]);
      printf("   total\t%d\n", stats.total);
      printf("   fragmented\t%d\n", stats.fragmented);
      printf("   nopayload\t%d\n", stats.nopayload);
      printf("   shorthdr\t%d\n", stats.shorthdr);
      printf("   toolong\t%d\n", stats.toolong);
      printf("   tooshort\t%d\n", stats.tooshort);
      printf("   unknown\t%d\n", stats.unknown_type);
      printf("   udp\t\t%d\n", stats.udp);
      printf("   tcp\t\t%d\n", stats.tcp);
      
    }
}

/* Local Variables:  */
/* mode:C */
/* c-file-style:"gnu" */
/* end: */
