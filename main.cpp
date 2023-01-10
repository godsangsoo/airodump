#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "mac.h"
#include <unordered_map>
#include <string>
#include <stdlib.h>
#include <iostream>

using namespace std;

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

struct Content{
	int Beacons; // +1
	string ESSID;
};

#pragma pack(push, 1)
struct Radiotap{
	uint8_t _version;
	uint8_t _pad;
	uint16_t _len;
	uint32_t _present;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct Beacon{
	uint16_t _version;
	uint16_t _pad;
	Mac _da;
	Mac _sa;
	Mac _bssid;
	// dummy
	uint8_t dummy[14];
};
#pragma pack(pop)

#pragma pack(push, 1)
struct Tagged{
	uint8_t _id;
	uint8_t _len;
};
#pragma pack(pop)

unordered_map <string, Content> bssid;

void usage() {
	printf("syntax : airodump <interface>\n");
	printf("sample : airodump mon0\n");
}

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void print_terminal() {
	system("clear");
	printf("BSSID\t\t\tBeacons\t\tESSID\n\n");
	for(auto _bssid : bssid) {
		cout << (string)_bssid.first << '\t' << _bssid.second.Beacons << "\t\t" << (string)_bssid.second.ESSID << "\t\n";
	}
}

string find_essid(const u_char* _tag, uint _len){
	#define ESSID 0x0

	string s;
	uint used_len = 0;
	while(used_len <= _len) {
		Tagged* tag = (Tagged*) (_tag + used_len);
		if(used_len + tag->_len > _len) break;
		if((tag->_id == ESSID) && (used_len + sizeof(Tagged) + tag->_len <= _len)) {
			for(uint i = 0; i < tag->_len; i++) {
				s.push_back(_tag[used_len + sizeof(Tagged) + i]);
			}
			break;
		}
		used_len += sizeof(Tagged) + tag->_len;
	}

	// if there is no essid, return empty string
	cout << s << endl;
	return s; 
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		Radiotap* radiotap = (Radiotap*)packet;
		Beacon* beacon = (Beacon*)(packet + (radiotap->_len));

		#define BEACON 0x0080
		if(radiotap->_len + sizeof(Beacon) > header->len) continue;

		if((beacon->_version) == BEACON) {
			auto it = bssid.find(string(beacon->_bssid));
			if(it == bssid.end()) {
				bssid.insert(
					{
						string(beacon->_bssid),
						{
							1, 
							find_essid(packet + radiotap->_len + sizeof(Beacon), header->len - radiotap->_len - sizeof(Beacon))
						}
					}
				); 
			}
			else (it->second.Beacons)++;
			print_terminal();
		}
	}

	pcap_close(pcap);
}
