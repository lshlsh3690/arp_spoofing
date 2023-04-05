#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>

#include<sys/socket.h>
#include<sys/types.h>
#include<arpa/inet.h>
#include<netinet/in.h>

#include<linux/ip.h>
#include<linux/tcp.h>

unsigned short in_cksum(u_short *addr, int len);

int main(void)
{
	unsigned char packet[40];
	int raw_socket;
	int on=1;
	struct iphdr *iphdr;
	struct tcphdr *tcphdr;
	struct sockaddr_in address;
	
	raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on));

	tcphdr = (struct tcphdr *)(packet + 20);
	
	memset(tcphdr, 0, sizeof(tcphdr));
	tcphdr->source = htons(9190);
	tcphdr->dest = htons(12345);
	tcphdr->seq = htonl(92929292);
	tcphdr->ack_seq = htonl(12121212);
	tcphdr->doff = 5;
	tcphdr->syn = 1;
	tcphdr->window = htons(512);
	tcphdr->check = 1;

	iphdr = (struct iphdr *)packet;

	memset((char *)iphdr, 0, sizeof(iphdr));
	iphdr->version = 4;
	iphdr->ihl -5;
	iphdr->protocol = IPPROTO_TCP;
	iphdr->tot_len = 40;
	iphdr->id = htons(777);
	iphdr->ttl = 60;
	iphdr->check = in_cksum((u_short *)iphdr, sizeof(struct iphdr));
	iphdr->saddr = inet_addr("192.168.126.131");
	iphdr->daddr = inet_addr("192.168.126.128");
	
	address.sin_family = AF_INET;
	address.sin_port = htons(12345);
	address.sin_addr.s_addr = inet_addr("192.168.126.128");

	sendto(raw_socket, &packet, sizeof(packet), 0x0, (struct sockaddr *)&address, sizeof(address));

	return 0;
}

unsigned short in_cksum(u_short *addr, int len)
{
	int sum=0;
	int nleft=len;
	u_short *w=addr;
	u_short answer=0;
	
	while(nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if(nleft == 1)
	{
		*(u_char *)(&answer) = *(u_char *)w;
		sum += answer;
	}
	
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}			
