#include "router-utils.h"
#include "sr_rt.h"
#include <stdint.h>
#include <iostream>

using namespace std;
uint32_t get_int(uint8_t * point){
	return (uint32_t)((point[0]<<24)|(point[1]<<16)|(point[2]<<8)|(point[3]));
}

unsigned short get_short(uint8_t * point){
	return (unsigned short)((point[0]<<8)|(point[1]));
}

unsigned char get_char(uint8_t * point){
	return (unsigned char)(point[0]);
}


uint32_t flip_ip(uint32_t ip){
	return (uint32_t)((ip>>24)|((ip&0xFF0000)>>8)|((ip&0xFF00)<<8)|(ip<<24));
}

struct sr_if * interface_match(struct sr_if * list, uint32_t ip){
	if(list){
		if(flip_ip(ip)==list->ip){
			return list;
		}else{
			return interface_match(list->next, ip);
		}
	}
	return NULL;
}

struct sr_rt* longest_match_aux(struct sr_rt* routing_table, uint32_t ip, struct sr_rt* found){
	if(routing_table){
		uint32_t prefix = routing_table->dest.s_addr & routing_table->mask.s_addr;
		uint32_t possible = ip & routing_table->mask.s_addr;
		if(prefix==possible){
			if(found){
				uint32_t tmp_prefix = found->dest.s_addr & found->mask.s_addr;
				if(tmp_prefix>prefix){
					return longest_match_aux(routing_table->next, ip, found);
				}else{
					return longest_match_aux(routing_table->next, ip, routing_table);
				}
			}else{
				return longest_match_aux(routing_table->next, ip, routing_table);
			}
			
		}else{
			return longest_match_aux(routing_table->next, ip, found);
		}
	}
	return found;
}

struct sr_rt* longest_match(struct sr_rt* routing_table, uint32_t ip){
	return longest_match_aux(routing_table, flip_ip(ip), NULL);
}