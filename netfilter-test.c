#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "iphdr.h"
#include "tcphdr.h"

char *target_host;

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data) {
    
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *packet_data;
    int len;

    ph = nfq_get_msg_packet_hdr(nfa);
    uint32_t id = ntohl(ph->packet_id);

    len = nfq_get_payload(nfa, &packet_data);

    if(len >= 0) {
        // 3. IP 헤더 분석
        struct iphdr *ip = (struct iphdr *)packet_data;

        // TCP 프로토콜(6)인지 확인
        if(ip->protocol == 6) {
            // IP 헤더 길이 계산 
            int ip_len = ip->ihl * 4;
            struct tcphdr *tcp = (struct tcphdr *)(packet_data + ip_len);

            // 4. TCP 헤더 분석 (HTTP 포트 80인지 확인)
            if (ntohs(tcp->dest) == 80) {
                // TCP 헤더 길이 계산 
                int tcp_len = tcp->doff * 4;
                unsigned char *payload = (unsigned char *)tcp + tcp_len;
                int payload_len = len - ip_len - tcp_len;

                // 5. HTTP Payload 내 Host 필드 검사
                if (payload_len > 0) {
                    char *host_pos = strstr((char *)payload, "Host: ");
                    if (host_pos) {
                        if (strstr(host_pos, target_host)) {
                            printf("!!! found something to block : %s !!!\n", target_host);
                            return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                        }
                    }
                }
            }
        }
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char* argv[]){
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096];

    if(argc != 2){
        fprintf(stderr, "Usage: %s <host>\n", argv[0]);
        return 1;
    }
    target_host = argv[1];

    h = nfq_open();

    if (!h){
        fprintf(stderr, "cant open handle\n");
        return 1;
    }

    if(nfq_bind_pf(h, AF_INET) < 0){
        fprintf(stderr, "error during nfq_bind_pf()");
        return 1;
    }

    qh = nfq_create_queue(h, 0, &cb, NULL);
    if(!qh){
        fprintf(stderr, "cant make queue\n");
        return 1;
    }

    if(nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0){
        fprintf(stderr, "cant remove packet to qh");
        return 1;
    }

    fd = nfq_fd(h); //통로 아이디 가져오기
    while((rv = recv(fd, buf, sizeof(buf), 0))){
        if(rv >= 0){
            nfq_handle_packet(h, buf, rv);
        }
    }

    nfq_destroy_queue(qh);
    nfq_close(h);

    return 0;
}
