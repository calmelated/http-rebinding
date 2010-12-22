#ifndef __WEB_REBINDING_INFO__
#define __CONN_REDIRECT_INFO__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/ioctl.h>    
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/types.h>

#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <linux/if_ether.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h> 
#include <time.h>
#include <unistd.h>

#include "csman.h"
#include "csid/csid_gid.h"
#include "csid/csid_local.h"   
#include "unilog.h"  

#define ENABLE_ICMP_REPLY 0
#define ENABLE_SYN_ACK_REPLY 1
#define ENABLE_HTTP_REPLY 1
#define REPLY_AUTHORITATIVE 1
#define ENABLE_DEBUG 0
#define ENABLE_ERROR 1

#if ENABLE_DEBUG == 1
#define ddebug(args...)   fprintf(stderr, args)
#else
#define ddebug(args...)
#endif    

#if ENABLE_ERROR == 1
#define error(args...)   fprintf(stderr, args)
#else
#define error(args...)
#endif  

#define TARGET_IFACE        "br0"
#define HTTP_RE_PID         "/var/run/web-rebinding.pid"
#define REDIRECT_PAGE       "webrb.htm"
#define PKT_BUF_LEN         10240
#define MAX_URL_RULE        16
#define PSEUDO              sizeof(struct pseudo_hdr)
#define TCPHDR              sizeof(struct tcphdr)
#define Z_NL                4294967295
#define PERIOD_SIZE			1
#define PERIOD				"."

#define IPV4_ADDR_LEN		0x0004
#define DNS_REPLY_FLAGS		0x8180
#define DNS_REPLY_REFUSED	0x8183
#define DNS_REPLY_NAME		0xC00C
#define DNS_REPLY_TTL		0x0005
#define DNS_CLASS_IN		0x0001
#define DNS_TYPE_A		    0x0001
#define DNS_TYPE_NS		    0x0002
#define DNS_TYPE_PTR		0x000C
#define DNS_TYPE_AAAA		0x001C
#define DNS_NUM_ANSWERS		0x0002
#define NAMESERVER_ONE		"ns1"
#define NAMESERVER_TWO		"ns2"
#define WWW			        "www"
#define NS_NAME_ONE		    "\x03ns1\xC0\x0C"
#define NS_NAME_TWO		    "\x03ns2\xC0\x0C"
#define NS_NAME_LEN		    0x0006
#define MAX_DNS_QUESTIONS	1

#define UNKNOWN_REQUEST	    0
#define DNS_REQUEST	        1
#define HTTP_REQUEST        2
#define ICMP_REQUEST        3
#define SYN_REQUEST         4

struct dns_header {
	uint16_t xid;
	uint16_t flags;
	uint16_t num_questions;
	uint16_t num_answers;
	uint16_t num_authority;
	uint16_t num_additional;
};

struct dns_question_section {
	uint16_t type;
	uint16_t class;
};

struct dns_answer_section {
	uint16_t name;
	uint16_t type;
	uint16_t class;
	uint16_t ttl_top;
	uint16_t ttl;
	uint16_t data_len;
};    

struct dns_authoritative {
	uint16_t name;
	uint16_t type;
	uint16_t class;
	uint16_t ttl_top; // for alignment
	uint16_t ttl;
	uint16_t data_len;
	uint16_t data;
};   

struct tcp_rec {
    unsigned int tcp_len;
    unsigned int ack;
    unsigned int seq;
};   

struct dns_rec {
	uint16_t type;
	uint16_t class; 
    char domain_name[256];
};

struct icmp_rec {
	uint16_t seq;
	uint16_t id; 
}; 

struct conn_info {
    char src_ip[16];
    int  src_port;
    char dst_ip[16];
    int dst_port;
    int  protocol;
    union {
        struct tcp_rec tcpinfo;
        struct dns_rec dnsinfo;
        struct icmp_rec icmpinfo;
    };
};   

struct pseudo_hdr {
    unsigned long saddr;
    unsigned long daddr;
    char reserved;
    unsigned char protocol;
    unsigned short length;
};
 
int get_conn_info (int nrecv, char *pkt_buffer, struct conn_info *cinfo);
int send_http_redirect(struct conn_info *cinfo, char* redirect_page);
int send_dns_reply(char *pkt_buffer, int nrecv, struct conn_info *cinfo_, char* redirect_ip);
int send_icmp_reply(char *pkt_buffer, int nrecv, struct conn_info *cinfo_);
int send_syn_ack(struct conn_info *cinfo_);

#endif 
