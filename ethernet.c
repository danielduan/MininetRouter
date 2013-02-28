#import "ethernet.h"

EthernetFrame::EthernetFrame(uint8_t * packet, int len){
	
}
EthernetFrame::EthernetFrame(string dst, string src, string pld){

}
EthernetFrame::EthernetFrame(){

}

void EthernetFrame::calculateCRC(){

}

void EthernetFrame::SetSource(){

}

void EthernetFrame::SetDest(){

}

void EthernetFrame::SetPayload(){

}

uint8_t * EthernetFrame::GetPacket(){

}

unsigned int EthernetFrame::GetLength(){

}

string EthernetFrame::GetPreamble(){

}

string EthernetFrame::GetDestAddress(){

}

string EthernetFrame::GetSrcAddress(){

}

string EthernetFrame::GetPayload(){

}

string EthernetFrame::GetCRC(){

}