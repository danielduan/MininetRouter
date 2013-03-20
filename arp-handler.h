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
	require_arp: Sends responses back using data in cache, or sends arp request if
	there is no entry for the request passed
*/
void require_arp(struct sr_instance *,  struct sr_arpreq *);
/*
	sends/re-send an ARP request if req was sent more than one second ago
*/
void request_arp(struct sr_instance * sr, struct sr_arpreq * req);
#endif