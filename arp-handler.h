#ifndef _ARP_HANDLER_
#define _ARP_HANDLER_

#include "ethernet.h" /* EthernetFrame */
#include "sr_router.h" /* sr_instance */
#include "sr_protocol.h" /* sr_arp_hdr_t */

/**
	handle_arp: handle all incoming ARP packets
*/
void handle_arp_packet(struct sr_instance *, EthernetFrame *, char *);

/**
	require_arp: Called when there isn't an ARP entry to send a packet (sr_router.c)
	Called every second in sr_arpcache_sweepreqs to resend or process already received
*/
void require_arp(struct sr_instance *,  struct sr_arpreq *);
/*
	puts out arp requests i'm guessing? - Daniel
*/
void request_arp(struct sr_instance * sr, struct sr_arpreq * req);
#endif