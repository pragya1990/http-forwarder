#include <stdio.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <ifaddrs.h>
typedef struct router_table_struct 
{	
	uint8_t port;	
	char ip[16];
}router_table_struct;

int counter=0;  //stores total number of unique ip addresses
#define ETHERNET_HEADER_LEN 14
#define TCP_PROTOCOL_VAL 6
#define WIRELESS_INTERFACE "eth1" ////////////////////////////////////////////////////////////////////////////////
#define ETHERNET_INTERFACE "eth0"
#define ETHER_ADDRESS_PATH_WIRELESS "/sys/class/net/eth1/address" /////////////////////////////////////////////////
#define ETHER_ADDRESS_PATH_LAN "/sys/class/net/eth0/address"
#define ROUTER_TABLE_PATH "/home/pragya/Documents/router/router_table.txt"
#define ETHER_ADDRESS_ROUTER "00:1e:40:d3:be:50"
#define ETHER_ADDRESS_PRAGYA_LAN "00:16:d3:04:b5:7d"
#define IP_PRAGYA_LAN "162.254.3.1"

u_char* modify_packet(u_char *pkt_ptr, pcap_t *eth_handle, pcap_t *wlan_handle, int pkt_type, int len, int caplen);
int change_ether_addr_dest(uint8_t pkt_type, struct ether_header *eth_hdr);
int change_ether_addr_source(uint8_t pkt_type, struct ether_header *eth_hdr);
int change_ip_addr(struct ip *ip_hdr, uint8_t pkt_type);
uint16_t ip_checksum(struct ip *ip_hdr);
uint16_t tcp_checksum(const u_char *pkt_ptr);
uint8_t* parse_ip_address(char *p);
uint8_t *parse_ether_address(char *ether_addr_str);
int check_if_packet_exists(char *ipaddr,  uint16_t port);
int add_entry_in_router_table(char *ipaddr, uint16_t port);
void get_ip_addr(struct ip *ip_hdr, uint8_t pkt_type, char *host);

int show_packet_contents(u_char *pkt_ptr, int len, int caplen);

int main() 
{ 
	struct pcap_pkthdr header; // The header that pcap gives us 
	u_char *pkt_ptr; // The actual packet 
	pcap_t *wlan_handle, *eth_handle;  
	char errbuf[PCAP_ERRBUF_SIZE]; 
	char *source_ip, *dest_ip;  //source ip address of the current packet
	uint8_t dest_port, source_port;
	eth_handle = pcap_open_live(ETHERNET_INTERFACE,65535,0, -1, errbuf);////////////////////////////////////////// changed it from (..., 65535, 1, 0, errbuf) --- date 6/12/2011
	wlan_handle = pcap_open_live(WIRELESS_INTERFACE,65535,0, -1,errbuf); //////////////////////////////////////////////
	if (eth_handle == NULL)
	{ 	printf("Couldn't open ethernet handle: %s\n",errbuf); 
      		return(2); 
	} 
	if (wlan_handle == NULL)
    	{ 	printf("Couldn't open wlan_handle: %s\n",errbuf); 
      		return(2); 
    	} 
	int c;
	
	pid_t pid = fork();
	
	if(pid == 0) /*** for reading packets from local LAN, forwarding them to wireless router and saving them ********/
  	{	c = 0;	
		while(c < 30)
   		{  	
			pkt_ptr = (u_char *)pcap_next(eth_handle,&header); //////////////////////////////////////////
			struct ether_header *eth_hdr = (struct ether_header *)pkt_ptr;
    			struct ip *ip_hdr = (struct ip *)(pkt_ptr + 14); //point to an IP header structure
    			struct tcphdr *tcp_hdr = (struct tcphdr *)(pkt_ptr + 14 + 20);
       		
			printf("local LAN count: %d: %s.%hu %d",c, inet_ntoa(ip_hdr->ip_src), ntohs(tcp_hdr->source),ntohs(ip_hdr->ip_len));
			printf(" : %s.%hu  version: %d\n", inet_ntoa(ip_hdr->ip_dst), ntohs(tcp_hdr->dest), ip_hdr->ip_v);
		
			dest_port = ntohs(tcp_hdr->dest);		
			source_ip = inet_ntoa(ip_hdr->ip_src);
			if(!strcmp(source_ip, IP_PRAGYA_LAN) && dest_port == 80) //////////////////////////////////
			{	
				u_char *ptr = modify_packet(pkt_ptr, eth_handle, wlan_handle, (uint8_t)1, header.len, header.caplen);
				int packets_injected = pcap_inject(wlan_handle,(const void *)ptr, header.len); ///////////
				printf("\ninjected: %d\n",packets_injected); 
				if(packets_injected == -1)
				{	printf("error: %s\n",pcap_geterr(wlan_handle)); ///////////////////////////////////
				}					
			}
			c++;
   		}  
	}
	else	/****** for reading packets from wireless router, checking if they need to be forwarded and forwarding them to local LAN*******/
	{	c = 0;	
		while(c < 100)
		{  	pkt_ptr = (u_char *)pcap_next(wlan_handle,&header); /////////////////////////////////////////
			struct ether_header *eth_hdr = (struct ether_header *)pkt_ptr;
    	
    			struct ip *ip_hdr = (struct ip *)(pkt_ptr + 14); //point to an IP header structure
    			struct tcphdr *tcp_hdr = (struct tcphdr *)(pkt_ptr + 14 + 20);
       		
			printf("Wireless count: %d: %s.%u %d",c, inet_ntoa(ip_hdr->ip_src), ntohs(tcp_hdr->source),ntohs(ip_hdr->ip_len));
			printf(" : %s.%u  version: %d\n", inet_ntoa(ip_hdr->ip_dst), ntohs(tcp_hdr->dest), ip_hdr->ip_v);

			char *ip_source=inet_ntoa(ip_hdr->ip_src);
			dest_port = ntohs(tcp_hdr->dest);
			if(check_if_packet_exists(ip_source, dest_port) && ntohs(tcp_hdr->source) == 80)
			{	
				u_char *ptr = modify_packet(pkt_ptr, eth_handle, wlan_handle, (uint8_t)0, header.len, header.caplen);

				int packets_injected = pcap_sendpacket(eth_handle,(const void *)ptr, header.len); ////////////
				printf("\ninjected: %d\n",packets_injected); 
				if(packets_injected == -1)
				{	printf("error: %s\n",pcap_geterr(eth_handle)); ///////////////////////////////////
				}	
			}
			c++;
   		}  
		waitpid(pid, NULL, 0);
		pcap_close(eth_handle);  
		pcap_close(wlan_handle);
	}
} 

uint16_t ip_checksum (struct ip *ip_hdr)
{	uint8_t *ipsrc_parse = parse_ip_address(inet_ntoa(ip_hdr->ip_src));
	uint8_t *ipdst_parse = parse_ip_address(inet_ntoa(ip_hdr->ip_dst));	

	 int sum = (((unsigned int)ip_hdr->ip_v<<12 | (unsigned int)ip_hdr->ip_hl<<8 | (ip_hdr->ip_tos)) +
			(ntohs(ip_hdr->ip_len))+
			(ntohs(ip_hdr->ip_id))+
			(ntohs(ip_hdr->ip_off))+
			((ip_hdr->ip_ttl)<<8 | (ip_hdr->ip_p))+
			(ipsrc_parse[0]<<8 | ipsrc_parse[1])+
			(ipsrc_parse[2]<<8 | ipsrc_parse[3])+
			(ipdst_parse[0]<<8 | ipdst_parse[1])+
			(ipdst_parse[2]<<8 | ipdst_parse[3]));
	
	int chk_sum = ((sum & 0x0000ffff) + ((sum & 0xffff0000)>>16));
	
	return (uint16_t)(~chk_sum);
}

uint8_t* parse_ip_address(char *ipaddr)
{	//printf("parse ip address\n");
	int i=-1, num = 0, p = 1,j=0;
	uint8_t *ipaddr_parse = malloc(sizeof(int)*4);
	char ch;
	do
	{	i++;
		ch = ipaddr[i];
		if(ch == '.' || ch == '\0')
		{	ipaddr_parse[j] = num;
			p = 1;
			num = 0;
			j++;	
		}
		else
		{	num = num*p + (ch-48);				
			if (p == 1) p = 10;
		}	
	} while(ipaddr[i]!='\0');
	//printf("\n%d %d %d %d\n",ipaddr_parse[0], ipaddr_parse[1], ipaddr_parse[2], ipaddr_parse[3]);
	return ipaddr_parse;
}

uint8_t *parse_ether_address(char *ether_addr_str)
{	//printf("parse ether address\n");
	int i =-1,c,j=0; 
	char ch;
	uint8_t num=0, *ether_addr = malloc(sizeof(int)*6);
	do
	{	i++;	
		ch = ether_addr_str[i];
		if(ch == ':' || ch == '\0')
		{	ether_addr[j] = num;
			num = 0;
			j++;
		}
		else
		{	c = (ch>57)? ch-87 : ch-48;
			num = num*16 + c;
		}
	} while(ether_addr_str[i] != '\0');
	
	printf("MAC- ");
	for(i=0;i<6;i++)
		printf("%x:",ether_addr[i]);
	printf("\n");

	return ether_addr;
}

int add_entry_in_router_table(char *ipaddr, uint16_t port)
{	//printf("add entry in router table\n");
	FILE *rtable_fp = fopen(ROUTER_TABLE_PATH,"a+");
	router_table_struct rtable_ptr;

	while((fscanf(rtable_fp, "%s %hhu", rtable_ptr.ip, &rtable_ptr.port )) !=EOF);
	
	fprintf(rtable_fp,"%s %hu\n", ipaddr, port);
	fclose(rtable_fp);
}

int check_if_packet_exists(char *ipaddr,  uint16_t port)
{	//printf("check if packet exists\n");
	FILE *rtable_fp = fopen(ROUTER_TABLE_PATH,"a+");
	router_table_struct rtable_ptr;

	while((fscanf(rtable_fp, "%s %hhu", rtable_ptr.ip, &rtable_ptr.port )) !=EOF) //to check if ip address is already mapped 
    	{ 	
		if(!strcmp(ipaddr,rtable_ptr.ip) && port == rtable_ptr.port)
 		{	fclose(rtable_fp);
			return 1;
		}
	}
	fclose(rtable_fp);
	return 0;
}

int change_ip_addr(struct ip *ip_hdr, uint8_t pkt_type)
{	//printf("inside change ip address\n");	
	char *host = malloc(sizeof(NI_MAXHOST));
	get_ip_addr(ip_hdr, pkt_type, host);

	inet_aton(host, &ip_hdr->ip_src);
}

void get_ip_addr(struct ip *ip_hdr, uint8_t pkt_type, char *host)
{
	struct ifaddrs *ifap;
	getifaddrs(&ifap);
	char *errbuf;
	char *iface = WIRELESS_INTERFACE;
	while(ifap != NULL)
	{	if(ifap->ifa_addr->sa_family == AF_INET && !strcmp(iface,ifap->ifa_name) )	
		{	getnameinfo(ifap->ifa_addr,sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
			printf("address: %s %s\n", host,ifap->ifa_name);
			break;
		}
		ifap = ifap->ifa_next;
	}
}

int change_ether_addr_source(uint8_t pkt_type, struct ether_header *eth_hdr)
{	//printf("change_ether_addr_source\n");	
	FILE *fp_ether;
	if(pkt_type == 0)
		fp_ether = fopen(ETHER_ADDRESS_PATH_LAN, "r");
	else
		fp_ether = fopen(ETHER_ADDRESS_PATH_WIRELESS, "r");
	char *ether_src = malloc(17);
	fscanf(fp_ether, "%s", ether_src);
	printf("%s\n",ether_src);
	fclose(fp_ether);
	
	uint8_t *ether_source = parse_ether_address(ether_src);
	int i;
	for(i=0;i<6;i++)
		eth_hdr->ether_shost[i] = ether_source[i];
}

int change_ether_addr_dest(uint8_t pkt_type, struct ether_header *eth_hdr)
{	//printf("inside change ether address dest\n");	
	uint8_t *ether_dest;	
	if(pkt_type == 0)
		ether_dest = parse_ether_address(ETHER_ADDRESS_PRAGYA_LAN); 
	else
		ether_dest = parse_ether_address(ETHER_ADDRESS_ROUTER); 
	int i;
	for(i=0;i<6;i++)
		eth_hdr->ether_dhost[i] = ether_dest[i];
}

u_char *modify_packet(u_char *pkt_ptr, pcap_t *eth_handle, pcap_t *wlan_handle, int pkt_type, int len, int caplen)
{	//printf("inside modify packet\n");
	
	printf("contents of the pakcet without modification: \n");
	show_packet_contents(pkt_ptr, len, caplen);

	//u_char *pkt_ptr = malloc(sizeof(pkt_ptr_old));
	//strcpy(pkt_ptr, pkt_ptr_old);	
	struct ether_header *eth_hdr = (struct ether_header *)pkt_ptr;
    	struct ip *ip_hdr = (struct ip *)(pkt_ptr + ETHERNET_HEADER_LEN); //point to an IP header structure
	
	printf("checksum before modification: %x\n",ip_checksum(ip_hdr));
	
	int header_len = (unsigned int)(ip_hdr->ip_hl*4);
    	struct tcphdr *tcp_hdr = (struct tcphdr *)(pkt_ptr + ETHERNET_HEADER_LEN + header_len);
	
	if(pkt_type == 0)
	{	inet_aton(IP_PRAGYA_LAN, &ip_hdr->ip_dst);
	}

	else
	{	if(!check_if_packet_exists(inet_ntoa(ip_hdr->ip_dst),(uint16_t)( ntohs(tcp_hdr->source)) ))
			add_entry_in_router_table(inet_ntoa(ip_hdr->ip_dst),(uint16_t)ntohs(tcp_hdr->source) );
		
		change_ip_addr(ip_hdr, pkt_type);
	}
	change_ether_addr_source(pkt_type, eth_hdr);
	change_ether_addr_dest(pkt_type, eth_hdr);
	
	uint16_t ip_sum = ip_checksum(ip_hdr);
	ip_hdr->ip_sum = htons(ip_sum);

	printf("contents of the pakcet after modification: \n");
	show_packet_contents(pkt_ptr, len, caplen);

	printf("checksum after modification: %x\n",ip_sum);

	uint16_t tcp_sum = tcp_checksum(pkt_ptr);
	tcp_hdr->check = htons(tcp_sum);
	printf("TCP checksum after modification: %x\n",tcp_hdr->check);
	printf("end of modify packet\n");


	return pkt_ptr;
}

uint16_t tcp_checksum(const u_char *pkt_ptr)
{	
	struct ip *ip_hdr = (struct ip *)(pkt_ptr + ETHERNET_HEADER_LEN); //point to an IP header structure
	int ip_header_len = (unsigned int)(ip_hdr->ip_hl)*4;	
	int len = ntohs(ip_hdr->ip_len) - ip_header_len;
	struct tcphdr *tcp_hdr = (struct tcphdr*)(pkt_ptr + ETHERNET_HEADER_LEN + ip_header_len);	
		
	pkt_ptr = pkt_ptr + ETHERNET_HEADER_LEN + ip_header_len;	
	uint8_t *pkt = (uint8_t *)pkt_ptr;
	printf("\n");
	uint16_t val16=0;
	int val32=0, i=0;
	tcp_hdr->check = 0;	
	for(i=0;i<(len/2);i++)
	{	
		val16 = 0;			 
		val16 = (val16 | (*pkt)) << 8;
		pkt += 1; 
		val16 = val16 | (*pkt);
		//printf("%x\n",val16);
		pkt +=1;
		val32 = val32 + val16;
	}
	if(len%2 == 1)
	{
		val16 = 0;
		val16 = (val16 | (*pkt)) << 8;
		val32 = val32 + val16;
	}
	//printf("half sum: %x\n",val32);

	uint8_t *ipsrc_parse = parse_ip_address(inet_ntoa(ip_hdr->ip_src));
	uint8_t *ipdst_parse = parse_ip_address(inet_ntoa(ip_hdr->ip_dst));

	val32 = val32 + (ipsrc_parse[0]<<8 | ipsrc_parse[1])+ (ipsrc_parse[2]<<8 | ipsrc_parse[3])+
			(ipdst_parse[0]<<8 | ipdst_parse[1])+ (ipdst_parse[2]<<8 | ipdst_parse[3]) + 
			(uint16_t)TCP_PROTOCOL_VAL + (uint16_t)len;	
	
	printf("32 bit sum: %x\n",val32);
	uint16_t high,low;
	while(1)
	{	high = (uint16_t)(val32 >> 16);
		if(high == 0)
			break;
		low = (uint16_t)((val32 << 16) >> 16);
		val32 = low + high;
	}
	uint16_t comp_sum = 0xffff & ~(val32);
	printf("sum: %x comp:%x\n", val32, comp_sum);
	return comp_sum;
}


int show_packet_contents(u_char *pkt_ptr, int len, int caplen)
{	
	struct ether_header *eth_hdr = (struct ether_header *)pkt_ptr;
    	struct ip *ip_hdr = (struct ip *)(pkt_ptr + ETHERNET_HEADER_LEN); //point to an IP header structure
	
	int header_len = (int)(ip_hdr->ip_hl*4);
    	struct tcphdr *tcp_hdr = (struct tcphdr *)(pkt_ptr + ETHERNET_HEADER_LEN + header_len);

	int j=0;
	
	printf("Packet length: %d caplen: %d\n",len,caplen);

	printf("ethernet source: ");
	int i;
	for(i=0;i<6;i++)
		printf("%x:",eth_hdr->ether_shost[i]);
	printf("\n");
	printf("ethernet dest: ");
	for(i=0;i<6;i++)
		printf("%x:",eth_hdr->ether_dhost[i]);
	printf("\nethernet type: %x\n", ntohs(eth_hdr->ether_type));
	printf("\n\n");
	
	printf("IP PACKET CONTENTS\n");	

	printf("IP version      : %x\n",(unsigned int)ip_hdr->ip_v);
	printf("IP Header length: %x\n",(unsigned int)ip_hdr->ip_hl);
	printf("IP tos          : %x\n",(uint8_t)(ip_hdr->ip_tos));
	printf("IP Packet length: %x\n",(uint16_t)ntohs(ip_hdr->ip_len));
	printf("IP Id           : %x\n",(uint16_t)ntohs(ip_hdr->ip_id));
	printf("IP offset       : %x\n",(uint16_t)ntohs(ip_hdr->ip_off));
	printf("IP TTL          : %x\n",(uint8_t)(ip_hdr->ip_ttl));
	printf("IP protocol     : %x\n",(uint8_t)(ip_hdr->ip_p));
	printf("IP checksum     : %x\n",(uint16_t)ntohs(ip_hdr->ip_sum));
	printf("IP src_addr     : %s\n",inet_ntoa(ip_hdr->ip_src));
	printf("IP dst_addr     : %s\n",inet_ntoa(ip_hdr->ip_dst));

	printf("TCP_PACKET_CONTENTS\n");
	printf("source port: %hu\n",(uint16_t)ntohs(tcp_hdr->source));
	printf("destination port: %hu\n",(uint16_t)ntohs(tcp_hdr->dest));
}

