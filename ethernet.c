#include "ethernet.h" /* EthernetFrame class prototype */
#include "sr_utils.h"
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <string>
#include <stdint.h>
#include <stdlib.h>

#include <errno.h>

using namespace std;

EthernetFrame::EthernetFrame(uint8_t * packet, size_t len){
	rawPacket = NULL;
	if(len<14){
		type = BAD_PACKET;
		cerr << "Incomplete ethernet packet" << endl;
		return;
	}
	if(packet[12]==0x08&&packet[13]==0x06){
		type = ARP_PACKET;
	}else if(packet[12]==0x08&&packet[13]==0x00){
		type = IP_PACKET;
	}else{
		type = BAD_PACKET;
		return;
	}
	rawPacket = new uint8_t[len];
	memcpy(rawPacket, packet, len);
	memcpy(destination, rawPacket, 6);
	memcpy(source, rawPacket+6, 6);
	payloadLength = len - 14;
	payload = packet+14;
}

EthernetFrame::EthernetFrame(uint8_t * dest, uint8_t * source, uint8_t * payload, size_t length, enum packet_type it){	
	rawPacket = NULL;
	memcpy(destination,dest,6);
	memcpy(this->source, source, 6);
	this->payload = new uint8_t[length];
	memcpy(this->payload, payload, length);
	payloadLength = length;
	this->type = it;
	rawPacket = GetPacket();
}

uint8_t * EthernetFrame::GetPacket(){
	if(!IsValid()) return NULL;
	if(rawPacket){
		delete rawPacket;
	}
	uint8_t tmp[2];
	rawPacket = new uint8_t[payloadLength+14];
	memcpy(rawPacket, destination, 6);
	memcpy(rawPacket+6, source, 6);
	if(type==IP_PACKET){
		tmp[0]=0x08;
		tmp[1]=0x00;
	}else{
		tmp[0]=0x08;
		tmp[1]=0x06;
	}
	memcpy(rawPacket+12,tmp,2);
	memcpy(rawPacket+14, payload, payloadLength);
	return rawPacket;
}

size_t EthernetFrame::PayloadLength(){
	return payloadLength;
}

uint8_t * EthernetFrame::GetDestAddress(){
	return destination;
}

uint8_t * EthernetFrame::GetSrcAddress(){
	return source;
}

uint8_t * EthernetFrame::GetPayload(){
	return payload;
}

int EthernetFrame::IsValid(){
	return type!=BAD_PACKET;
}

enum packet_type EthernetFrame::GetType(){
	return type;
}

EthernetFrame::~EthernetFrame(){
	if(rawPacket){
		delete rawPacket;
	}
}



void EthernetFrame::print_hex() {
	cout << "Working Print hex" << endl;
    for(size_t i = 0; i < 14+payloadLength; i++) {
        printf("%02x ", rawPacket[i]);
        if(i&&i%32==0) printf("\n");
    }
    printf("\n");
}