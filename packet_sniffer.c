#include <stdio.h>
#include <pcap.h>
#include <winsock2.h>
#include <windows.h>

// structure declarations for different headers VVV

// ethernet header
struct ethernet_header {
    // whos the packets going to, whos sending it, and what type of packet is it
    unsigned char dest_mac[6];
    unsigned char src_mac[6];
    unsigned short type;
};

// ip header
struct ip_header {
    unsigned char ver_ihl;      // how long the header is what version of ip it is
    unsigned char tos;          // the type of service
    unsigned short total_len;   // total size of the packet
    unsigned short id;          // id num to reassemble fragments
    unsigned short flags_offset; // fragmentation for if the packet gets split up
    unsigned char ttl;          // the time to live aka how many routers it can go through
    unsigned char protocol;     // what protocol aka udp, tcp, icmp...
    unsigned short checksum;    // error check
    unsigned int src_ip;        // sender ip
    unsigned int dest_ip;       // destination ip
};

// tcp header
struct tcp_header {
    unsigned short src_port; // source port
    unsigned short dest_port; // destination port
    unsigned int seq_num; // sequence number
    unsigned int ack_num; // acknowledgement number
    unsigned char offset_reserved; //how long the header is
    unsigned char flags; // 3 way handhake flags
    unsigned short window; // how much data can be recieved
    unsigned short checksum; // error checking
    unsigned short urgent; // urgent pointer
};

// callback that runs for every packet
void packet_handler(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *packet) {
    struct ethernet_header *eth;
    struct ip_header *ip;
    struct tcp_header *tcp;
    
    printf("\n============================================================\n");
    
    // the ethernet layer
    eth = (struct ethernet_header*)packet;
    printf("MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x -> %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
           eth->src_mac[0], eth->src_mac[1], eth->src_mac[2],
           eth->src_mac[3], eth->src_mac[4], eth->src_mac[5],
           eth->dest_mac[0], eth->dest_mac[1], eth->dest_mac[2],
           eth->dest_mac[3], eth->dest_mac[4], eth->dest_mac[5]);
    
    // check if its ip packet
    if (ntohs(eth->type) == 0x0800) {
    
        ip = (struct ip_header*)(packet + 14);  // Skip Ethernet header
        printf("IP: %d.%d.%d.%d -> %d.%d.%d.%d\n",
               (ip->src_ip >> 0) & 0xFF, (ip->src_ip >> 8) & 0xFF,
               (ip->src_ip >> 16) & 0xFF, (ip->src_ip >> 24) & 0xFF,
               (ip->dest_ip >> 0) & 0xFF, (ip->dest_ip >> 8) & 0xFF,
               (ip->dest_ip >> 16) & 0xFF, (ip->dest_ip >> 24) & 0xFF);
        printf("TTL: %d\n", ip->ttl);
        
        // checking for tcp
        if (ip->protocol == 6) {
            int ip_header_len = (ip->ver_ihl & 0x0F) * 4;
            tcp = (struct tcp_header*)(packet + 14 + ip_header_len);
            printf("TCP: %d -> %d\n", ntohs(tcp->src_port), ntohs(tcp->dest_port));
            printf("Flags: %c%c\n",
                   (tcp->flags & 0x02) ? 'S' : '-',  // SYN
                   (tcp->flags & 0x10) ? 'A' : '-'); // ACK
        }
    }
}

int main() {
    pcap_if_t *alldevs;
    pcap_if_t *dev;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int dev_num = 1;
    
    printf("packet sniffer in C\n");
    printf("============================================================\n");
    
    // locating all network devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Error finding devices: %s\n", errbuf);
        return 1;
    }
    
    // listing all devices
    printf("\nAvailable network devices:\n");
    for (dev = alldevs; dev != NULL; dev = dev->next) {
        printf("%d. %s\n", dev_num++, dev->description ? dev->description : dev->name);
    }
    
    printf("\nchoose a number for your device: ");
    int choice;
    scanf("%d", &choice);
    
    // choose what you want to actually sniff
    dev_num = 1;
    for (dev = alldevs; dev != NULL; dev = dev->next) {
        if (dev_num == choice) break;
        dev_num++;
    }
    
    if (!dev) {
        printf("Invalid choice\n");
        pcap_freealldevs(alldevs);
        return 1;
    }
    
    // opening the device for packet capture
    handle = pcap_open_live(dev->name, 65536, 1, 1000, errbuf);
    if (!handle) {
        printf("Error opening device: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }
    
    printf("\nsniffer active. press ctrl+c to stop.\n");
    printf("============================================================\n");
    
    // begin capturing packets
    pcap_loop(handle, 0, packet_handler, NULL);
    
    // post cleanup
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    
    return 0;
}