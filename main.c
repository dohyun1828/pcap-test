#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
/* 이더넷 주소는 6 바이트입니다 */ 
	#define ETHER_ADDR_LEN 6 
#define IP_RF 0x8000 /* 예약 된 프래그먼트 플래그 */
#define IP_DF 0x4000 /* 조각화 플래그를 지정하지 않음 */ 
#define IP_MF 0x2000 /* 조각화 플래그를 더 지정 */ 
#define IP_OFFMASK 0x1fff /* 마스크 */ 
#define IP_HL(ip) (((ip)-> ip_vhl) & 0x0f) 
#define IP_V(ip) (((ip)-> ip_vhl) >> 4) 
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4) 
#define SIZE_ETHERNET 14


int main(int argc, char * argv[])
{

while(1)
{
/* 이더넷 헤더 */ 
struct sniff_ethernet { 
	u_char ether_dhost [ETHER_ADDR_LEN]; /* 대상 호스트 주소 */ 
	u_char ether_shost [ETHER_ADDR_LEN]; /* 소스 호스트 주소 */ 
	u_short ether_type; /* IP? ARP? RARP? etc */ 
								}; 

/* IP 헤더 */ 
struct sniff_ip { 
	u_char ip_vhl; /* 버전 << 4 | 헤더 길이 >> 2 */ 
	u_char ip_tos; /* 서비스 유형 */ 
	u_short ip_len; /* 총 길이 */ 
	u_short ip_id; /* 식별 */ 
	u_short ip_off; /* 프래그먼트 오프셋 필드 */ 
	u_char ip_ttl; /* 생방송 시간 */ 
	u_char ip_p; /* 프로토콜 */ 
	u_short ip_sum; /* 체크섬 */ 
	struct in_addr ip_src, ip_dst; /* 소스와 목적지 주소 */ 
}; 
/* TCP 헤더 */ 
typedef u_int tcp_seq; 

struct sniff_tcp { 
	u_short th_sport; /* 소스 포트 */ 
	u_short th_dport; /* 대상 포트 */ 
	tcp_seq th_seq; /* 시퀀스 번호 */
	tcp_seq th_ack; /* 승인 번호 */ 
	u_char th_offx2; /* 데이터 오프셋, rsvd */ 
	u_char th_flags; 
};
	const struct sniff_ethernet * ethernet; /* 이더넷 헤더 */ 
	const struct sniff_ip * ip; /* IP 헤더 */ 
	const struct sniff_tcp * tcp; /* TCP 헤더 */ 
	const u_char *payload; /* 패킷 페이로드 */ 
	u_int size_ip;
	u_int size_tcp;
	char * dev, errbuf[PCAP_ERRBUF_SIZE];
	dev = pcap_lookupdev(errbuf);
	if (dev==NULL)
	{
		fprintf(stderr, "기본 장치를 찾을 수 없습니다 : %s\n", errbuf);
		return (2);
	}
	printf("장치 : %s\n", dev);
	pcap_t * handle;
	handle = pcap_open_live(dev, BUFSIZ, 1, 10000, errbuf);
	if(handle==NULL)
	{
	fprintf(stderr, "%s\n 장치를 열 수 없습니다. : %s\n", dev, errbuf);
	return 2; 
	}

	const u_char * packet;
	struct pcap_pkthdr header;
	int res=pcap_next_ex(handle, &header, &packet);
	if(res=0) continue;
	if(res == -1 || res == -2) break;
	packet = pcap_next(handle, &header);
	ethernet = (struct sniff_ethernet *)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if(size_ip < 20)
	{
		printf("*Invalid IP header length: %u bytes\n", size_ip);
		return 2;
	}
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20)
	{
		printf("*Invalid TCP header length: %u bytes\n", size_tcp);
		return 2;
	}
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	printf("mac_dst: %02X:%02X:%02X:%02X:%02X:%02X\n",
	(unsigned)ethernet->ether_dhost[0],
	(unsigned)ethernet->ether_dhost[1],
	(unsigned)ethernet->ether_dhost[2],
	(unsigned)ethernet->ether_dhost[3],
	(unsigned)ethernet->ether_dhost[4],
	(unsigned)ethernet->ether_dhost[5]);
	printf("mac_src: %02X:%02X:%02X:%02X:%02X:%02X\n",
	(unsigned)ethernet->ether_shost[0],
	(unsigned)ethernet->ether_shost[1],
	(unsigned)ethernet->ether_shost[2],
	(unsigned)ethernet->ether_shost[3],
	(unsigned)ethernet->ether_shost[4],
	(unsigned)ethernet->ether_shost[5]);
	u_int ipsrc,ipdst;
	ipsrc=ntohl(ip->ip_src.s_addr);
	ipdst=ntohl(ip->ip_dst.s_addr);
	printf("ip_src: %d.%d.%d.%d\n",ipsrc>>24, (u_char)(ipsrc>>16),(u_char)(ipsrc>>8), (u_char)(ipsrc));
	printf("ip_dst: %d.%d.%d.%d\n",ipdst>>24, (u_char)(ipdst>>16),(u_char)(ipdst>>8), (u_char)(ipdst));
	printf("port_dst: %d\n",ntohs(tcp->th_dport));
	printf("port_src: %d\n",ntohs(tcp->th_sport));
	pcap_close(handle);
	const int payload_sz = ntohs(ip->ip_len) - (size_ip + size_tcp);
	if(payload_sz == 0) return;
	printf("<payload>\n");
	int len = payload_sz < 32 ? payload_sz : 32;
	for(int i=1; i<len;i++)
	{
		printf("%02X ", payload[i-1]);
		if(i%0x10 == 0)
			printf("\n");
	}
	printf("\n");

}
return 0;
}
