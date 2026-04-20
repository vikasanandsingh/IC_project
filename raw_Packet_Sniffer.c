#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <time.h>

void print_header(FILE *f) {
    fprintf(f, "Protocol | Source IP       | SrcPort | Destination IP | DstPort | Info\n");
    fprintf(f, "-------------------------------------------------------------------------------\n");
}

int main(){
    
    unsigned char buffer[65536];
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sock<0){ perror("Socket"); return 1;}

    // Timestamp log file
    char fname[64];
    time_t now = time(NULL);
    strftime(fname, sizeof(fname), "capture_%Y%m%d_%H%M%S.txt", localtime(&now));
    FILE *f = fopen(fname, "w");
    if (!f) { perror("fopen"); return 1; }

    print_header(f);

    for(int i = 0; i<60 ; i++) {

        int len = recvfrom(sock, buffer, sizeof(buffer), 0,
                            &saddr, (socklen_t *)&saddr_len);
        if (len < 0) { perror("recvfrom"); break;}

        struct ethhdr *eth = (struct ethhdr *)buffer;

        /* ARP  */
        if(ntohs(eth->h_proto) == ETH_P_ARP) {
            struct ether_arp *arp = (struct ether_arp *)(buffer + sizeof(struct ethhdr));

            fprintf(f, "ARP     | %-15s |   -   | %-15s |   -   | ARP Who-has/Reply\n",
                    inet_ntoa(*(struct in_addr *)arp->arp_spa),
                    inet_ntoa(*(struct in_addr *)arp->arp_tpa));
            continue;
        }

        /*IPv6*/
        if(ntohs(eth->h_proto)==0x86DD){
            fprintf(f,"IPv6    | (IPv6 src)      |   -   | (IPv6 dst)      |   -   | IPv6 Packet\n");
            continue;
        }
        /*IPv4*/
        if(ntohs(eth->h_proto)!=ETH_P_IP)
            continue;

        struct iphdr*iph=(struct iphdr*)(buffer + sizeof(structethhdr));
        struct sockaddr_in_src,dst;
        src.sin_addr.s_addr=iph->saddr;
        dst.sin_addr.s_addr=iph->daddr;

        switch (iph->protocol) {
            /*TCP*/
            case 6: {
                struct tcphdr*tcp = (void*)iph + iph->ihl*4;

                fprintf(f,"TCP     | %-15s | %-6d | %-15s | %-6d |SYN=%d ACK=%d\n",
                        inet_ntoa(src.sin_addr), ntohs(tcp->source),
                        inet_ntoa(dst.sin_addr), ntohs(tcp->dest),
                        tcp->syn, tcp->ack;
            //HTTP Detection//
                unsigned char*payload = (unsigned char*)tcp + tcp->doff*4;
                int payload_len = len-(payload-buffer);

                if(payload_len > 0 && (memcmp(payload,"GET",3) == 0 || memcmp(paylaod,"POST",4) == 0)){
                    fprintf(f,"HTTP    |%-15s|%-6d|%-15s|%-6d| HTTP Request\n",
                            inet_ntoa(src.sin_addr), ntohs(tcp->source),
                            inet_ntoa(dst.sin_addr), ntohs(tcp->dest));
                }
                break;
        } 
            /*UDP */
            case 17: {
                struct udphdr *udp = (void *)iph + iph->ih1 * 4;
                fprintf(f, "UDP     | %-15s | %-6d | %-15s | %-6d | Len=%d\n",
                        inet_ntoa(src.sin_addr), ntohs(udp->source),
                        inet_ntoa(dst.sin_addr), ntohs(udp->dest),
                        ntohs(udp->len));
                break;
            }
            
    }
    }

    fclose(f);
    close(sock);
    return 0;
}
