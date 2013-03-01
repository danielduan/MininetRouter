#include "ethernet.h" /* EthernetFrame Prototype */
#include "sr_utils.h" /* cksum */
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <string>
#include <stdint.h>
#include <stdlib.h>

using namespace std;

/*
	string rawPacket;
	size_t payloadLength;
	string destination;
	string source;
	string payload;
	uint16_t FCS;
*/

EthernetFrame::EthernetFrame(uint8_t * packet, size_t len){
	rawPacket = "";
	if(len<64||len>1518) return; // Invalid ethernet packet
	char * tmp = new char[len];
	memcpy(tmp, packet, len);
	rawPacket = string(tmp);
	delete tmp;
	destination = rawPacket.substr(0,6);
	source = rawPacket.substr(6,12);
	payloadLength = (size_t) atoi(rawPacket.substr(12,14).c_str());
	if(rawPacket.length()<(14+payloadLength+4)){ // incomplete packet
		rawPacket = ""; 
		return;
	}
	payload = rawPacket.substr(14,payloadLength);
	FCS = (uint16_t) atoi(rawPacket.substr(payloadLength, payloadLength+4).c_str());
}

EthernetFrame::EthernetFrame(string dst, string src, string pld){
	
}

EthernetFrame::EthernetFrame(){

}

uint16_t EthernetFrame::GetFCS(){
	return cksum(payload.c_str(), payload.length());
}

void EthernetFrame::SetSource(string str){

}

void EthernetFrame::SetDest(string str){

}

void EthernetFrame::SetPayload(string str){

}

string EthernetFrame::GetPacket(){
	return "";
}

size_t EthernetFrame::GetLength(){
	return 0;
}

string EthernetFrame::GetDestAddress(){
	return "";
}

string EthernetFrame::GetSrcAddress(){
	return "";
}

string EthernetFrame::GetPayload(){
	return "";
}

int EthernetFrame::IsValid(){
	if(rawPacket.length()<64) return 0;
	return this->GetFCS()==FCS;
}