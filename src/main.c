#include <pthread.h>
#include "pcap.h"
#include <stdio.h>
#include "beacon.c"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#define NULL "\0"
#define EHTERNET_LEN 24
#define FIXED_PARAM_LEN 12
#define FIELD_JUMP_LEN 2

struct wifiList{
    unsigned char BSSID[6];
    unsigned int beaconCnt;
    int PWR;
    unsigned char lastPacket[10];
    unsigned int channel;
    unsigned char ESSID[32];
};
struct wifiList wifi_list[500];
int count = 0;  //와이파이 목록 개수
char * dev;
int PWR;
int channel;
time_t start;
unsigned char lastPacket_time[10];

void usage(){   // 프로그램 사용법 출력 함수
    printf("syntax: ./airodump-ng <interface>\n");
    printf("sample: ./airodump-ng wlan0\n");
}

void monitor(){ // 랜카드 모니터 모드로 변경 함수
    char command[100];
    sprintf(command, "ifconfig %s down",dev);
    system(command);
    sprintf(command, "iwconfig %s mode monitor",dev);
    system(command);
    sprintf(command, "ifconfig %s up",dev);
    system(command);
}

void* channel_hopping(void * dev){ //모든 채널의 패킷을 받기 위한 채널 호핑 함수
    int cnt = 1;
    while(1){
            char command[100];
            if (cnt>13) cnt=1;
            sprintf(command, "iwconfig %s ch %d", (char *)dev, cnt);
            system(command);
            cnt++;
            sleep(2);
    }
}

void list(){    //와이파이 목록 출력 함수
    unsigned char bssid[20];
    unsigned char currentTime[40];
    time_t seconds = time(0);
    struct tm *now = localtime(&seconds);
    sprintf(&currentTime, "%04d-%02d-%02d %02d:%02d", 1900 + now->tm_year, now->tm_mon + 1, now->tm_mday, now->tm_hour, now->tm_min);
    if (count == 0){
        printf("검색된 Wi-fi가 없습니다. \n\n");
    }else{
        printf("\n CH %2d ][ Elapsed: %d mins ][ %s ][ interface %s \n", channel, (seconds-start)/60, currentTime, dev);
        printf("\n BSSID\t\t     PWR  Beacons   CH   Last  ESSID\n\n");
        for (int i = 0; i < count; i++){
            sprintf(&bssid, "%02x:%02x:%02x:%02x:%02x:%02x", wifi_list[i].BSSID[0], wifi_list[i].BSSID[1], wifi_list[i].BSSID[2],
                                                            wifi_list[i].BSSID[3], wifi_list[i].BSSID[4], wifi_list[i].BSSID[5]);
            printf(" %-18s %4d  %7d   %2d  %5s  %-32s\n", bssid, wifi_list[i].PWR, wifi_list[i].beaconCnt, wifi_list[i].channel, wifi_list[i].lastPacket , wifi_list[i].ESSID);
        }
    }
}

int search(unsigned char * BSSID){  //이미 목록에 있는 와이파이인지 확인하는 함수
    char bssid[20];
    char bssid_compare[20];
    sprintf(&bssid, "%02x:%02x:%02x:%02x:%02x:%02x", BSSID[0], BSSID[1], BSSID[2], BSSID[3], BSSID[4], BSSID[5]);
    int struct_len = sizeof(wifi_list) / sizeof(struct wifiList);
    for(int i=0; i<struct_len; i++){
        sprintf(&bssid_compare, "%02x:%02x:%02x:%02x:%02x:%02x", wifi_list[i].BSSID[0], wifi_list[i].BSSID[1], wifi_list[i].BSSID[2],
                                                        wifi_list[i].BSSID[3], wifi_list[i].BSSID[4], wifi_list[i].BSSID[5]);
        if(strcmp(bssid,bssid_compare)==0){
            wifi_list[i].beaconCnt += 1;
            wifi_list[i].PWR = PWR;
            memcpy(wifi_list[i].lastPacket, lastPacket_time, 10);
            return 1;
        }
    }
    return 0;
}

void append(unsigned char * ESSID, unsigned char * BSSID){  //와이파이 목록에 추가하는 함수
    count++;
    for (int i=0;i<6;i++) wifi_list[count-1].BSSID[i] = BSSID[i];
    wifi_list[count-1].PWR = PWR;
    wifi_list[count-1].channel = channel;
    memcpy(wifi_list[count-1].lastPacket, lastPacket_time, 10);
    memcpy(wifi_list[count-1].ESSID,ESSID,32);
}


int main(int argc, char* argv[]) {
    start = time(0);
    if (argc != 2) { // 인자가 2개가 아니면 사용법 출력
        usage();
        return -1;
    }
    dev = argv[1]; // 네트워크 인터페이스
    char errbuf[PCAP_ERRBUF_SIZE];

    if(strlen(dev)>30){ // 버퍼 오버플로우 방지
        printf("interface name length less than 30 characters");
        return -1;
    }

    monitor(); // 모니터 모드 변경
    pthread_t thread;
    pthread_create(&thread, 0, channel_hopping, dev); // 채널 호핑

    pcap_t* pcap = pcap_open_live(dev , BUFSIZ, 1, 1000, errbuf); // pcap open
    if (pcap == NULL) { // 오류 시 종료
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
    }

    while (1) { // 802.11 패킷 수신
        struct pcap_pkthdr* header;
        const u_char* packet;
        unsigned int radiotap_len, frame_control, SSID_len, support_len, DS_len;
        unsigned char SSID_str[32];
        unsigned char BSSID_str[6];
        time_t seconds = time(0);
        struct tm *now= localtime(&seconds);
        sprintf(&lastPacket_time, "%02d:%02d", now->tm_hour, now->tm_min);

        int res = pcap_next_ex(pcap, &header, &packet); // 다음 패킷 수신
        if (res == 0) continue; // 패킷 버퍼 시간 초과 만료 -> 다시 패킷 수신
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) { // 오류 및 EOF -> 종료
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        //printf("%u bytes captured\n", header->caplen);
        PWR = packet[18]-256;

        radiotap_len = radiotap_length((struct radiotap_header *)packet); // Get radiotap length
        packet += radiotap_len;

        frame_control = beacon_header_length((struct beacon_header *)packet);
        struct beacon_header * BSSID = (struct beacon_header *)packet;
        for(int i=0;i<6;i++) {
            BSSID_str[i] = BSSID->bssid[i];
        }
        if (frame_control == 0x8000){   //beacon frame
            packet += EHTERNET_LEN;
            fixed_parameters_length((struct fixed_parameters *) packet);
            packet += FIXED_PARAM_LEN;
            //switch(tag_parameter_number(packet))
            SSID_len = dump_SSID_parameter((struct tag_SSID_parameter *) packet);

            //SSID를 배열에 저장하는 부분
            struct tag_SSID_parameter * SSID = (struct tag_SSID_parameter *) packet;
            for(int i=0;i<SSID_len;i++) SSID_str[i] = SSID->ssid[i];
            SSID_str[SSID_len] = '\0';
            if (SSID_str[0] == '\0') continue;

            packet += SSID_len + FIELD_JUMP_LEN;
            support_len = dump_supported_rates((struct tag_supported_rates *) packet);
            packet += support_len + FIELD_JUMP_LEN;
            DS_len = dump_DS_parameter((struct tag_DS_parameter *) packet);
            struct tag_DS_parameter * DS = (struct tag_DS_parameter *) packet;
            channel = DS->channel;  //현 패킷의 와이파이 채널을 저장
            if (search(BSSID_str)==0){  //0을 리턴하면 현재 와이파이 목록에 없는 BSSID 이므로, 추가해서 목록을 재출력
                append(SSID_str, BSSID_str);
            }
            system("clear");
            list();
        }
    }
    pcap_close(pcap);
}
