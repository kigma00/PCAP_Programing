#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

//ethernet Header
#pragma pack(push,1)
struct ethheader{
    uint8_t ether_dmac[6];
    uint8_t ether_smac[6];
    uint16_t ether_type;
};
#pragma pack(pop)

//ip Header
#pragma pack(push,1)
struct ipheader{
    uint8_t headerLength : 4, Version : 4 ;
    uint8_t TypeofService;
    uint16_t TotalLength;
    uint16_t Identifier;
    uint16_t Flags : 3, fragmentOffset : 13;
    uint8_t TTL;
    uint8_t ProtocolID;
    uint16_t HeaderChecksum;
    uint8_t sip[4];
    uint8_t dip[4];
};
#pragma pack(pop)

//tcp Header
#pragma pack(push,1)
struct tcpheader{
    uint16_t sport;
    uint16_t dport;
    uint32_t SequenceNumber;
    uint32_t AcknowledgementNumber;
    uint8_t fHLEN:4, tHLEN:4;
};
#pragma pack(pop)

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
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

        struct ethheader* rth = packet;
        struct ipheader* iph = (packet + sizeof(struct ethheader));
        struct tcpheader* tcph = (packet + sizeof(struct ethheader) + sizeof(struct ipheader));

        if(iph->ProtocolID == IPPROTO_TCP && ntohs(rth->ether_type) == 0x0800)
        {
            printf("===================================================================\n\n");
            printf("<source Info>\n");
            printf("source mac address : %02x:%02x:%02x:%02x:%02x:%02x\n", rth->ether_smac[0], rth->ether_smac[1], rth->ether_smac[2], rth->ether_smac[3], rth->ether_smac[4], rth->ether_smac[5]);
            printf("source ip address : %d.%d.%d.%d\n", iph->sip[0], iph->sip[1], iph->sip[2], iph->sip[3]);
            printf("source port : %d\n", ntohs(tcph->sport));
            printf("\n");

            printf("<destination Info>\n");
            printf("destination mac address : %02x:%02x:%02x:%02x:%02x:%02x\n", rth->ether_dmac[0], rth->ether_dmac[1], rth->ether_dmac[2] ,rth->ether_dmac[3] ,rth->ether_dmac[4] ,rth->ether_dmac[5]);
            printf("destination ip address : %d.%d.%d.%d\n", iph->dip[0], iph->dip[1], iph->dip[2], iph->dip[3]);
            printf("destination port : %d\n", ntohs(tcph->dport));
            printf("\n");

            /*Num Test
            printf("iphl : %d\n", iph->headerLength);
            printf("ntohs iptotl %d\n", ntohs(iph->TotalLength));
            printf("iptotl %d\n", iph->TotalLength);
            printf("tcpHLEN : %d\n", tcph->tHLEN*4);
            printf("size of Total L :%d\n", sizeof(iph->TotalLength));
            printf("\n");
            */

            printf("<data field>\n");
            int data_length = ntohs(iph->TotalLength) - (iph->headerLength*4) - (tcph->tHLEN*4);
            if (data_length > 16)
                data_length = 16;
            printf("data_length : %d\n", data_length);
            for(int i=0 ; i < data_length ; i++){
                printf("%02x ", packet[sizeof(struct ethheader) + (iph->headerLength*4) + (tcph->tHLEN*4) + i]);
            }
            printf("\n");
        }
    }

    pcap_close(pcap);
    return 0;
}
