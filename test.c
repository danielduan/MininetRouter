#include <iostream>
#include <stdio.h>
#include "ethernet.h"

//using namespace std;

int main(){
	uint8_t data[] = {'1','2','3','4'};
	EthernetFrame * frame = new EthernetFrame(data,4);
	cout << "End" << endl;
	return 0;
}