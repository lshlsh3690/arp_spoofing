#include<stdio.h>
#include<fcntl.h>
#include<unistd.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<stdlib.h>
#include<netinet/ether.h>
#include<sys/ioctl.h>			//하드웨어의 정보를 구하는 함수를 ㄱ지고 있음
#include<string.h>

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
	struct ip_header *ip1;
	struct tcp_header *tcp1;
	int packet[60];
	int on=1;

	sock = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
	if(sock == -1)
	{
		printf("sock err \n");
		exit(1);
	}
	
	if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on))== -1)
	{
		printf("setsockopt err\n");
		exit(1);
	}

	//arp1=(struct arp_header *)(packet);
	//memset((char*)arp1, 0, sizeof(arp1));
	//eth1=(struct ethernet_header *)(packet);
	//memset((char*)eth1, 0, sizeof(eth1));
	ip1=(struct ip_header *)(packet);
	memset((char*)ip1, 0, sizeof(ip1));
	tcp1=(struct tcp_header *)(packet + 20);
	memset((char*)tcp1, 0, sizeof(tcp1));
	
	/*
	eth1->dest[0] = 0xFF;		eth1->dest[1] = 0xFF;
	eth1->dest[2] = 0xFF;		eth1->dest[3] = 0xFF;
	eth1->dest[4] = 0xFF;		eth1->dest[5] = 0xFF;

	eth1->source[0] = 0x00;		eth1->source[1] = 0x0c;
	eth1->source[2] = 0x29;		eth1->source[3] = 0x75;
	eth1->source[4] = 0x05;		eth1->source[5] = 0x90;

	eth1->protocol[0] = 0x08;	eth1->protocol[1] = 0x06;
	*/
	ip1->ip_header_len = 5;
	ip1->ip_version = 4;
	ip1->ip_tos = 0;//IPPROTO_TCP;
	ip1->ip_total_length = 60;
	ip1->ip_id=htons(123);//임의의 값
	ip1->ip_ttl=60;
	ip1->ip_checksum=1;
	ip1->ip_srcaddr = inet_addr("192.168.126.131");
	ip1->ip_dstaddr = inet_addr("192.168.126.128");
	

	tcp1->source_port = htons(9190);//임의의 값
	tcp1->dest_port = htons(1524);//임의의 값
	tcp1->sequence = htonl(12121212);//10자리 미만의 임의의값
	tcp1->acknowledge = htonl(12121212);
	tcp1->data_offset = 5;
	tcp1->syn = 1;
	tcp1->window = htons(512);
	tcp1->checksum = 1;
	/*
	arp1->hardware = 0x0001;	arp1->protocol = 0x0800;
	arp1->hardware_length = 0x06;	arp1->protocol_length = 0x04;
	arp1->operation_code = 0x01;
	arp1->send_MAC[0] = 0x00;	arp1->send_MAC[1] = 0x0c;
	arp1->send_MAC[2] = 0x29;	arp1->send_MAC[3] = 0x75;
	arp1->send_MAC[4] = 0x05;	arp1->send_MAC[5] = 0x90;
	
	arp1->send_IP[0] = 0xC0;	arp1->send_IP[1] = 0xA8;
	arp1->send_IP[2] = 0x7E;	arp1->send_IP[3] = 0x83;

	arp1->dest_MAC[0] = 0x00;	arp1->dest_MAC[1] = 0x00;
	arp1->dest_MAC[2] = 0x00;	arp1->dest_MAC[3] = 0x00;
	arp1->dest_MAC[4] = 0x00;	arp1->dest_MAC[5] = 0x00;
	
	arp1->dest_IP[0] = 0xC0;	arp1->dest_IP[1] = 0xA8;
	arp1->dest_IP[2] = 0x7E;	arp1->dest_IP[3] = 0x80;
	*/
	

	//sendto 함수를 사용하여 전송받을 주소의 구조체	
	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family=AF_INET;
	sock_addr.sin_addr.s_addr=inet_addr("192.168.126.128");
	sock_addr.sin_port=htons(4000);
	//4000번 포트를 쓰겠음
	
	sendto(sock, &packet, sizeof(packet), 0x0, (struct sockaddr*)&sock_addr, sizeof(sock_addr));
	
	
	return 0;	
}

