#include<stdio.h>
#include<fcntl.h>
#include<unistd.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<stdlib.h>
#include<netinet/ether.h>
#include<sys/ioctl.h>			//하드웨어의 정보를 구하는 함수를 ㄱ지고 있음
#include<string.h>

void print_ip_header(struct ip_header * ip);
void print_tcp_header(struct tcp_header * tcp);

struct ip_header{
	u_char ip_header_len:4;		//ip헤더의 길이를 32비트로 나타
	u_char ip_version:4;		//ip 버전 IPv4는 4
	u_char ip_tos;			//IP type of service
	u_short ip_total_length;	//total length
	u_short ip_id;			//ip id
	u_char ip_frag_offset:5;	//
	u_char ip_more_fragment:1;	
	u_char ip_dont_frragment:1;
	u_char ip_reserved_zero:1;
	u_char ip_frag_offset1;
	
	u_char ip_ttl;			//time to live;
	u_char ip_protocol;		//protocol
	u_short ip_checksum;		//ip checksum
	u_int ip_srcaddr;		//출발지 주소
	u_int ip_dstaddr;		//목적지 주소
};
struct arp_header{
	u_short hardware;		//hardware type 0x00 0x01 2byte;
	u_short protocol;		//protocol type 0x00 0x04 2byte
	u_char	hardware_length;	//hardware length 0x06 1byte
	u_char	protocol_length;	//protocol length 0x04 1byte
	u_short operation_code;		//operation code
	u_char	send_MAC[6];		//send MAC;
	u_char 	send_IP[4];		//send IP;
	u_char	dest_MAC[6];		//dest MAC;
	u_char	dest_IP[4];		//dest IP;
};

struct ethernet_header{
	u_char dest[6];			//dest addr;
	u_char source[6];		//source addr;
	u_char protocol[2];		//protocol;
};

struct tcp_header{
	u_short source_port;
	u_short dest_port;
	u_int sequence;
	u_int acknowledge;
	u_char ns:1;
	u_char reserved_part1:3;
	u_char data_offset:4;
	u_char fin:1;
	u_char syn:1;
	u_char rst:1;
	u_char psh:1;
	u_char ack:1;
	u_char urg:1;
	u_char ecn:1;
	u_char cwr:1;
	u_short window;
	u_short checksum;
	u_short urgent_pointer;
};

int main()
{
	int sock, serv_sock;
	struct sockaddr_in sock_addr, serv_sock_addr;
	struct arp_header *arp1;
	struct ethernet_header *eth1;
	struct ip_header *ip1, *ip2;
	struct tcp_header *tcp1, *tcp2;
	u_char packet[40];
	u_char *re_packet;
	int on=1;

	int packet_size = (sizeof(struct tcp_header) + sizeof(struct ip_header));
	re_packet = (u_char *)malloc(sizeof(packet_size));

	if((serv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
	{
		printf("serv_sock err\n");
		exit(1);	
	}

	while(1)
	{		
		memset(re_packet, 0, packet_size);
		unsigned int len=sizeof(serv_sock_addr);
		recvfrom(serv_sock, re_packet, packet_size, 0x0, (struct sockaddr *)&serv_sock_addr, &len);
		if (serv_sock < 0)
		{
			printf("recv from err\n");
			exit(1);
		}
	
		ip2=(struct ip_header *)(re_packet);
		tcp2=(struct tcp_header *)(re_packet+ ip2->ip_header_len * 4);
		
	
		print_ip_header(ip2);
		print_tcp_header(tcp2);
	}

	close(serv_sock);

	return 0;	
}

void print_ip_header(struct ip_header *ip)
{
	printf("[IP  HEADER] 버전 : %1u 헤더 길이 : %2u 프로토콜 : %3u", ip->ip_version, ip->ip_header_len, ip->ip_protocol);
	printf("출발 IP : %15s  ", inet_ntoa(*(struct in_addr *)&ip->ip_srcaddr));
	printf("도착 IP : %15s\n", inet_ntoa(*(struct in_addr *)&ip->ip_dstaddr));	
}

void print_tcp_header(struct tcp_header *tcp)
{
	printf("[TCP HEADER] 출발 포트 : %5u  도착 포트 : %5u ", ntohs(tcp->source_port), ntohs(tcp->dest_port));
	
	(tcp->urg == 1) ? printf("U"):printf("-");
	(tcp->ack == 1) ? printf("A"):printf("-");
	(tcp->psh == 1) ? printf("P"):printf("-");
	(tcp->rst == 1) ? printf("R"):printf("-");
	(tcp->syn == 1) ? printf("S"):printf("-");
	(tcp->fin == 1) ? printf("F"):printf("-");

	printf("\n\n");
}
