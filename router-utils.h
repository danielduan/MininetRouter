#ifndef _ROUTER_UTILS_
#define _ROUTER_UTILS_

#include "sr_rt.h"
#include "sr_if.h"

#include <stdint.h>
/**
	get_int: Will take the first 32 bits of the array and turn them into an unsigned integer
*/
uint32_t get_int(uint8_t *);

/**
	get_short: Will take the first 16 bits of the array and turn them into an unsigned short
*/
unsigned short get_short(uint8_t *);

/**
	get_char: Will take the first 8 bits of the array and turn them into an unsigned char
*/
unsigned char get_char(uint8_t *);

/**
	flip_ip: Flips the octets in the given IP. The reason is that the routing table stores
	the IPs in this format: D.C.B.A, this function turns the ip into A.B.C.D
*/
uint32_t flip_ip(uint32_t);

/**    
	interface_match: returns the table row that matches the given IP, null otherwise
*/
struct sr_if* interface_match(struct sr_if*, uint32_t);

/**    
	longest_match: returns the table row that matches the given IP, null otherwise
*/
struct sr_rt* longest_match(struct sr_rt*, uint32_t);

#endif