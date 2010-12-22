/*
 * Web Rebinding
 *
 * Redirect all the DNS/IMCP/HTTP requests of LAN PC to the Gateway
 *
 * Author: Chad Sheu
 * Last Modify: 2010/12/09
 */

#include "web_rebinding.h"
                 
static struct conn_info *cinfo;  
static unsigned short check_sum(unsigned short* data, int nbytes);
static int fill_address(int domain, const char* address, unsigned short port, struct sockaddr_in* sin);
static unsigned int build_pseudo_hdr(unsigned int src_addr, unsigned int dst_addr, unsigned int protocol,
                                     const unsigned char* hdr_data, unsigned int hdr_len, 
                                     const unsigned char* msg_data, unsigned int msg_len, 
                                     unsigned short** buffer); 

static unsigned char* build_udp_data(struct sockaddr_in* src_sin, struct sockaddr_in* dst_sin, 
                                     const unsigned char* msg, unsigned int msg_size);

#if ENABLE_HTTP_REPLY == 1 
static unsigned char* build_http_data(struct sockaddr_in* src_sin, struct sockaddr_in* dst_sin, 
                                     const unsigned char* msg, unsigned int msg_size);
#endif

#if ENABLE_SYN_ACK_REPLY == 1 
static unsigned char* build_tcp_synack (struct sockaddr_in* src_sin, struct sockaddr_in* dst_sin, 
                                        const unsigned char* msg, const unsigned int msg_size);
#endif

#if ENABLE_ICMP_REPLY == 1
static unsigned char* build_icmp_data (struct sockaddr_in* src_sin, struct sockaddr_in* dst_sin, 
                                       const unsigned char* msg, const unsigned int msg_size);
#endif               

/* Create DNS reply packet and send it to the client */
int send_dns_reply(char *pkt_buffer, int nrecv, struct conn_info *cinfo_, char* redirect_ip)
{
    cinfo = cinfo_;
    srand(time(0));  

    int s = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if (s <= 0) {
        perror("[open_sockraw] socket()");
        return 1;
    }  

    int enable = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) < 0) {
        perror("Error: setsockopt() - Cannot set HDRINCL:\n");
        goto end;
    } 

    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *) &enable, sizeof(enable)) < 0) {
        perror("Error: setsockopt() - Cannot reuse port ! \n");
        goto end;
    }
   
    // build up out source and destination sock addresses
    struct sockaddr_in src_sin;
    struct sockaddr_in dst_sin;
    fill_address(PF_INET, cinfo->dst_ip, htons(cinfo->dst_port), &src_sin);
    fill_address(PF_INET, cinfo->src_ip, htons(cinfo->src_port), &dst_sin);  

    char *request_packet = pkt_buffer + 14 + 20 +8;
    int request_packet_size = nrecv - 14 - 20 - 8;

	/* Zero out the answer section structure */
	struct dns_answer_section answer;
	memset(&answer,0,sizeof(struct dns_answer_section));
	int answer_size = sizeof(struct dns_answer_section);

	/* Check to make sure the packet size is of a valid length */
    int hdrlen = sizeof(struct dns_header) + 
                 sizeof(struct dns_question_section) + 
                 strlen(cinfo->dnsinfo.domain_name);
	if(request_packet_size < hdrlen) { 
        goto end;
    }
        
    /* Create the DNS answer section */
    answer.name = htons(DNS_REPLY_NAME);
    answer.type = cinfo->dnsinfo.type;
    answer.class = htons(DNS_CLASS_IN);
    answer.ttl = htons(DNS_REPLY_TTL);

    int num_answer = 0;
	int memcpy_offset = 0;
    int addr_len = 0;
	int reply_packet_size = 0;
	char *reply_packet = NULL;
	in_addr_t ip_address1 = inet_addr(redirect_ip);
	in_addr_t ip_address2 = inet_addr(redirect_ip);

    /* Data is an IPv4 address */
    if(cinfo->dnsinfo.type == htons(DNS_TYPE_A)){
        num_answer = DNS_NUM_ANSWERS;
        addr_len = IPV4_ADDR_LEN;
        answer.data_len = htons(IPV4_ADDR_LEN);
    }
    else if(cinfo->dnsinfo.type == htons(DNS_TYPE_NS)){
        num_answer = DNS_NUM_ANSWERS;
        addr_len = NS_NAME_LEN;
        answer.data_len = htons(NS_NAME_LEN);         
    }
    else if(cinfo->dnsinfo.type == htons(DNS_TYPE_PTR) || 
            cinfo->dnsinfo.type == htons(DNS_TYPE_AAAA)){
        ddebug("Don't support PTR/IPv6 !!\n");
        num_answer = 0;
        reply_packet_size = request_packet_size;
        if((reply_packet = malloc(reply_packet_size)) != NULL) {
            memcpy(reply_packet,request_packet,request_packet_size);
            memcpy_offset = request_packet_size;  
            goto send_reply;
        }
        else {
            perror("Malloc Failure");
            goto end;
        } 
    }

    /* DNS response packet consists of the original DNS query plus the answer section,
     * plus the answer data (an IPv4 address). We have two IP addresses, so there are
     * two answer sections.
     */
    #if REPLY_AUTHORITATIVE == 1
        struct dns_authoritative authorit;
        memset(&authorit, 0, sizeof(struct dns_authoritative));
        int authorit_size = sizeof(struct dns_authoritative); 

        authorit.name = htons(DNS_REPLY_NAME);
        authorit.type = htons(DNS_TYPE_NS);
        authorit.class = htons(DNS_CLASS_IN);
        authorit.ttl = htons(DNS_REPLY_TTL);  
        authorit.data_len = htons(2); 
        authorit.data = htons(DNS_REPLY_NAME); 
 
        reply_packet_size = request_packet_size + 
                            ((answer_size + addr_len) * DNS_NUM_ANSWERS) + 
                            ((authorit_size) * 1); 
    #else
        reply_packet_size = request_packet_size + ((answer_size + addr_len) * DNS_NUM_ANSWERS);
    #endif

    if((reply_packet = malloc(reply_packet_size)) != NULL) {
        /* Memcpy packet data into the reply packet */
        memcpy(reply_packet,request_packet,request_packet_size);
        memcpy_offset += request_packet_size;

        memcpy(reply_packet+memcpy_offset,(void *) &answer,answer_size);
        memcpy_offset += answer_size;

        memcpy(reply_packet+memcpy_offset,(void *) &ip_address1, addr_len);
        memcpy_offset += addr_len;

        memcpy(reply_packet+memcpy_offset,(void *) &answer,answer_size);
        memcpy_offset += answer_size;

        memcpy(reply_packet+memcpy_offset,(void *) &ip_address2, addr_len);
        memcpy_offset += addr_len;
 
        #if REPLY_AUTHORITATIVE == 1
            memcpy(reply_packet + memcpy_offset,(void *) &authorit, authorit_size);
            memcpy_offset += authorit_size;  
        #endif            
    } 
    else {
        perror("Malloc Failure");
        goto end;
    }
 
    struct dns_header *header = NULL;
send_reply:
    /* Change the number of answers and the flags values of the DNS packet header */
    header = (struct dns_header *) reply_packet;
    header->num_answers = htons(num_answer);
    header->num_authority = htons(0);
    header->num_additional = htons(0);
    if(cinfo->dnsinfo.type == htons(DNS_TYPE_A)){
        header->num_authority = htons(1);
    }

    header->flags = htons(DNS_REPLY_FLAGS);
    ddebug("replay_pakcet size %d\n", memcpy_offset);

    unsigned char* data = build_udp_data(&src_sin, &dst_sin, reply_packet, memcpy_offset);
    unsigned int pkt_size = sizeof(struct ip) + sizeof(struct udphdr) + memcpy_offset;
    if (sendto(s, data, pkt_size, 0, (struct sockaddr*) &dst_sin, sizeof(dst_sin)) < 0) {
        error("Error with sendto() -- %s (%d)\n", strerror(errno), errno);
    }
    free(data);

end:    
    // We no longer need root privileges
    setuid(getuid()); 
    close(s); 
	return 0;
}    

#if ENABLE_SYN_ACK_REPLY == 1
int send_syn_ack(struct conn_info *cinfo_) 
{
    cinfo = cinfo_;
    srand(time(0));

    // root-privileges needed for the following operation
    int s = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s <= 0) {
        perror("[open_sockraw] socket()");
        return 1;
    }

    int enable = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) < 0) {
        perror("Error: setsockopt() - Cannot set HDRINCL:\n");
        close(s);
        return 1;
    }

    // build up out source and destination sock addresses
    struct sockaddr_in src_sin;
    struct sockaddr_in dst_sin;
    fill_address(PF_INET, cinfo->dst_ip, htons(cinfo->dst_port), &src_sin);
    fill_address(PF_INET, cinfo->src_ip, htons(cinfo->src_port), &dst_sin);

    // build our TCP datagram
    char msg[2] = "";
    unsigned char* data = build_tcp_synack(&src_sin, &dst_sin, msg, 0);
    unsigned int pkt_size = sizeof(struct ip) + sizeof(struct tcphdr);
    if (sendto(s, data, pkt_size, 0, (struct sockaddr*) &dst_sin, sizeof(dst_sin)) < 0) {
        fprintf(stderr, "Error with sendto() -- %s (%d)\n", strerror(errno), errno);
    }

    // We no longer need root privileges
    setuid(getuid());      
    free(data);
    close(s);
    return 0;
} 
#endif  

#if ENABLE_HTTP_REPLY == 1
int send_http_redirect(struct conn_info *cinfo_, char* redirect_page) 
{
    cinfo = cinfo_;
    srand(time(0));

    // root-privileges needed for the following operation
    int s = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s <= 0) {
        perror("[open_sockraw] socket()");
        return 1;
    }

    int enable = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) < 0) {
        perror("Error: setsockopt() - Cannot set HDRINCL:\n");
        close(s);
        return 1;
    }

    // We no longer need root privileges
    setuid(getuid());

    // build up out source and destination sock addresses
    struct sockaddr_in src_sin;
    struct sockaddr_in dst_sin;
    fill_address(PF_INET, cinfo->dst_ip, htons(cinfo->dst_port), &src_sin);
    fill_address(PF_INET, cinfo->src_ip, htons(cinfo->src_port), &dst_sin);
 
    // build our TCP datagram
    unsigned char msg[128]; 
    snprintf(msg, 128, "HTTP/1.1 303\r\n"
                       "Content-Type: text/html\r\n"
                       "Connection: close\r\n"
                       "Location: %s\r\n", redirect_page);

    unsigned char* data = build_http_data(&src_sin, &dst_sin, msg, strlen(msg));
    unsigned int pkt_size = sizeof(struct ip) + sizeof(struct tcphdr) + strlen(msg);
    if (sendto(s, data, pkt_size, 0, (struct sockaddr*) &dst_sin, sizeof(dst_sin)) < 0) {
        fprintf(stderr, "Error with sendto() -- %s (%d)\n", strerror(errno), errno);
    }
    
    free(data);
    close(s);
    return 0;
} 
#endif     

#if ENABLE_ICMP_REPLY == 1
int send_icmp_reply(char *pkt_buffer, int nrecv, struct conn_info *cinfo_) 
{
    cinfo = cinfo_;
    srand(time(0));

    // root-privileges needed for the following operation
    int s = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s <= 0) {
        perror("[open_sockraw] socket()");
        return 1;
    }

    int enable = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) < 0) {
        perror("Error: setsockopt() - Cannot set HDRINCL:\n");
        close(s);
        return 1;
    }

    // We no longer need root privileges
    setuid(getuid());

    // build up out source and destination sock addresses
    struct sockaddr_in src_sin;
    struct sockaddr_in dst_sin;
    fill_address(PF_INET, cinfo->dst_ip, htons(cinfo->dst_port), &src_sin);
    fill_address(PF_INET, cinfo->src_ip, htons(cinfo->src_port), &dst_sin);
 
    // build our TCP datagram
    unsigned char *msg = pkt_buffer + 14 + 20 + 8; 
    int msglen = nrecv - 14 - 20 - 8; 

    unsigned char* data = build_icmp_data(&src_sin, &dst_sin, msg, msglen);
    unsigned int pkt_size = sizeof(struct ip) + sizeof(struct icmphdr) + msglen;
    if (sendto(s, data, pkt_size, 0, (struct sockaddr*) &dst_sin, sizeof(dst_sin)) < 0) {
        fprintf(stderr, "Error with sendto() -- %s (%d)\n", strerror(errno), errno);
    }
    
    free(data);
    close(s);
    return 0;
} 
#endif    

static unsigned short check_sum(unsigned short* data, int nbytes) 
{
    unsigned long sum = 0;
    for (; nbytes > 1; nbytes -= 2) {
        sum += *data++;
    }

    if (nbytes == 1) {
        sum += *(unsigned char*) data;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}   

static int 
fill_address(int domain, const char* address, unsigned short port, struct sockaddr_in* sin)
{
    if (!address) {
        memset(sin, 0, sizeof(struct sockaddr_in));
        sin->sin_family = domain;
        sin->sin_addr.s_addr = htonl(INADDR_ANY);
        sin->sin_port = htons(port);
    }
    else {
        struct addrinfo hints;
        struct addrinfo* host_info = 0;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = domain;

        if (getaddrinfo(address, 0, &hints, &host_info) != 0 ||
            !host_info || !host_info->ai_addr || host_info->ai_family != domain)
        {
            if (host_info) {
                freeaddrinfo(host_info);
            }
            return -1;
        }

        memcpy(sin, host_info->ai_addr, sizeof(struct sockaddr_in));
        sin->sin_port = htons(port);
        freeaddrinfo(host_info);
    }
    return 0;
}

static unsigned int 
build_pseudo_hdr(unsigned int src_addr, unsigned int dst_addr, unsigned int protocol,
                 const unsigned char* hdr_data, unsigned int hdr_len, 
                 const unsigned char* msg_data, unsigned int msg_len, unsigned short** buffer)
{
    struct pseudo_hdr phdr;
    phdr.saddr    = src_addr;
    phdr.daddr    = dst_addr;
    phdr.reserved = 0;
    phdr.protocol = protocol;  
    phdr.length   = htons(hdr_len + msg_len);

    unsigned int buf_size = sizeof(struct pseudo_hdr) + hdr_len + msg_len;
    unsigned char* buf    = calloc(1, buf_size);
    int offset            = 0;

    memcpy(buf + offset, &phdr, sizeof(struct pseudo_hdr)); 
    offset += sizeof(struct pseudo_hdr);
    
    memcpy(buf + offset, hdr_data, hdr_len); 
    offset += hdr_len;
    
    memcpy(buf + offset, msg_data, msg_len);
    *buffer = (uint16_t*) buf;

    return buf_size;
}        

static unsigned char* 
build_udp_data (struct sockaddr_in* src_sin, struct sockaddr_in* dst_sin, 
                const unsigned char* msg, const unsigned int msg_size)
{
    const int ip_len = sizeof(struct ip) + sizeof(struct udphdr) + msg_size;
    unsigned char* datagram = calloc(1, ip_len);
    if (!datagram) {
        return 0;
    }

    // setup useful pointers to locations within the datagram
    struct ip* iph = (struct ip*) datagram;
    struct udphdr* udph = (struct udphdr*)(datagram + sizeof(struct ip));
    unsigned char* data = datagram + sizeof(struct ip) + sizeof(struct udphdr);

    // build IP header
    iph->ip_hl  = sizeof(struct ip) >> 2;
    iph->ip_v   = 4;
    iph->ip_tos = 0;
    iph->ip_len = htons(ip_len);
    iph->ip_id  = htons((int)(rand()/(((double)RAND_MAX + 1)/14095)));
    iph->ip_off = 0;
    iph->ip_ttl = 64;
    iph->ip_p   = IPPROTO_UDP;
    iph->ip_sum = 0;
    iph->ip_src.s_addr = src_sin->sin_addr.s_addr;
    iph->ip_dst.s_addr = dst_sin->sin_addr.s_addr;

    // now we compute the checksum for the IP header (albeit this is optional)
    iph->ip_sum = check_sum((unsigned short*) iph, sizeof(struct ip));

    // build TCP header
    udph->source  = htons(src_sin->sin_port);
    udph->dest    = htons(dst_sin->sin_port);
    udph->len     = htons(sizeof(struct udphdr) + msg_size);
    udph->check   = htons(0);

    // now we compute the UDP header checksum, across a pseudo message buffer, not the actual UDP header
    unsigned short* buffer = 0;
    unsigned int buffer_size = 
        build_pseudo_hdr(src_sin->sin_addr.s_addr, 
                         dst_sin->sin_addr.s_addr, 
                         IPPROTO_UDP,
                         (const unsigned char*) udph,       /* Protocol      */
                         sizeof(struct udphdr),             /* Header Size   */
                         msg,                               /* Conetent      */
                         msg_size,                          /* Message Size  */
                         &buffer);                          /* Pseudo Header */

    udph->check = check_sum(buffer, buffer_size);
    free(buffer);

    // add message data (if any)
    if (msg_size > 0) {
        memcpy(data, msg, msg_size);
    }
    return datagram; 
}

#if ENABLE_SYN_ACK_REPLY == 1 
static unsigned char* 
build_tcp_synack (struct sockaddr_in* src_sin, struct sockaddr_in* dst_sin, 
                  const unsigned char* msg, const unsigned int msg_size)
{
    const int ip_len = sizeof(struct ip) + sizeof(struct tcphdr) + msg_size;
    unsigned char* datagram = calloc(1, ip_len);
    if (!datagram) {
        return 0;
    }

    // setup useful pointers to locations within the datagram
    struct ip* iph = (struct ip*) datagram;
    struct tcphdr* tcph = (struct tcphdr*)(datagram + sizeof(struct ip));
    unsigned char* data = datagram + sizeof(struct ip) + sizeof(struct tcphdr);

    // build IP header
    iph->ip_hl  = sizeof(struct ip) >> 2;
    iph->ip_v   = 4;
    iph->ip_tos = 0;
    iph->ip_len = htons(ip_len);
    iph->ip_id  = htons((int)(rand()/(((double)RAND_MAX + 1)/14095)));
    iph->ip_off = 0;
    iph->ip_ttl = 64;
    iph->ip_p   = IPPROTO_TCP;
    iph->ip_sum = 0;
    iph->ip_src.s_addr = src_sin->sin_addr.s_addr;
    iph->ip_dst.s_addr = dst_sin->sin_addr.s_addr;

    // now we compute the checksum for the IP header (albeit this is optional)
    iph->ip_sum = check_sum((unsigned short*) iph, sizeof(struct ip));

    // build TCP header
    tcph->source  = htons(src_sin->sin_port);
    tcph->dest    = htons(dst_sin->sin_port);
    tcph->seq     = htonl(1); 
    tcph->ack_seq = htonl(cinfo->tcpinfo.seq + 1); 
    tcph->res1    = 0;
    tcph->doff    = sizeof(struct tcphdr) >> 2;
    tcph->fin     = 0;
    tcph->syn     = 1;
    tcph->rst     = 0;
    tcph->psh     = 0;
    tcph->ack     = 1;
    tcph->urg     = 0;
    tcph->res2    = 0;
    tcph->window  = htons(512);
    tcph->check   = 0;
    tcph->urg_ptr = htons(0);

    // now we compute the TCP header checksum, across a pseudo message buffer, not the actual TCP header
    unsigned short* buffer = 0;
    unsigned int buffer_size = 
        build_pseudo_hdr(src_sin->sin_addr.s_addr, 
                         dst_sin->sin_addr.s_addr, 
                         IPPROTO_TCP,
                         (const unsigned char*) tcph,       /* Protocol      */
                         sizeof(struct tcphdr),             /* Header Size   */
                         msg,                               /* Conetent      */
                         msg_size,                          /* Message Size  */
                         &buffer);                          /* Pseudo Header */

    tcph->check = check_sum(buffer, buffer_size);
    free(buffer);
    return datagram; 
}
#endif

#if ENABLE_HTTP_REPLY == 1 
static unsigned char* 
build_http_data (struct sockaddr_in* src_sin, struct sockaddr_in* dst_sin, 
                const unsigned char* msg, const unsigned int msg_size)
{
    const int ip_len = sizeof(struct ip) + sizeof(struct tcphdr) + msg_size;
    unsigned char* datagram = calloc(1, ip_len);
    if (!datagram) {
        return 0;
    }

    // setup useful pointers to locations within the datagram
    struct ip* iph = (struct ip*) datagram;
    struct tcphdr* tcph = (struct tcphdr*)(datagram + sizeof(struct ip));
    unsigned char* data = datagram + sizeof(struct ip) + sizeof(struct tcphdr);

    // build IP header
    iph->ip_hl  = sizeof(struct ip) >> 2;
    iph->ip_v   = 4;
    iph->ip_tos = 0;
    iph->ip_len = htons(ip_len);
    iph->ip_id  = htons((int)(rand()/(((double)RAND_MAX + 1)/14095)));
    iph->ip_off = 0;
    iph->ip_ttl = 64;
    iph->ip_p   = IPPROTO_TCP;
    iph->ip_sum = 0;
    iph->ip_src.s_addr = src_sin->sin_addr.s_addr;
    iph->ip_dst.s_addr = dst_sin->sin_addr.s_addr;

    // now we compute the checksum for the IP header (albeit this is optional)
    iph->ip_sum = check_sum((unsigned short*) iph, sizeof(struct ip));

    // build TCP header
    tcph->source  = htons(src_sin->sin_port);
    tcph->dest    = htons(dst_sin->sin_port);
    tcph->seq     = htonl(cinfo->tcpinfo.ack);              
    tcph->ack_seq = htonl(cinfo->tcpinfo.seq + cinfo->tcpinfo.tcp_len); 
    tcph->res1    = 0;
    tcph->doff    = sizeof(struct tcphdr) >> 2;
    tcph->fin     = 1;
    tcph->syn     = 0;
    tcph->rst     = 0;
    tcph->psh     = 0;
    tcph->ack     = 1;
    tcph->urg     = 0;
    tcph->res2    = 0;
    tcph->window  = htons(512);
    tcph->check   = 0;
    tcph->urg_ptr = htons(0);

    // now we compute the TCP header checksum, across a pseudo message buffer, not the actual TCP header
    unsigned short* buffer = 0;
    unsigned int buffer_size = 
        build_pseudo_hdr(src_sin->sin_addr.s_addr, 
                         dst_sin->sin_addr.s_addr, 
                         IPPROTO_TCP,
                         (const unsigned char*) tcph,       /* Protocol      */
                         sizeof(struct tcphdr),             /* Header Size   */
                         msg,                               /* Conetent      */
                         msg_size,                          /* Message Size  */
                         &buffer);                          /* Pseudo Header */

    tcph->check = check_sum(buffer, buffer_size);
    free(buffer);

    // add message data (if any)
    if (msg_size > 0) {
        memcpy(data, msg, msg_size);
    }
    return datagram;
}
#endif

#if ENABLE_ICMP_REPLY == 1
static unsigned char* 
build_icmp_data (struct sockaddr_in* src_sin, struct sockaddr_in* dst_sin, 
                const unsigned char* msg, const unsigned int msg_size)
{
    const int ip_len = sizeof(struct ip) + sizeof(struct icmp) + msg_size;
    unsigned char* datagram = calloc(1, ip_len);
    if (!datagram) {
        return 0;
    }

    // setup useful pointers to locations within the datagram
    struct ip* iph = (struct ip*) datagram;
    struct icmp* icmph = (struct icmp*)(datagram + sizeof(struct ip));
    unsigned char* data = datagram + sizeof(struct ip) + sizeof(struct icmp);

    // build IP header
    iph->ip_hl  = sizeof(struct ip) >> 2;
    iph->ip_v   = 4;
    iph->ip_tos = 0;
    iph->ip_len = htons(ip_len);
    iph->ip_id  = htons((int)(rand()/(((double)RAND_MAX + 1)/14095)));
    iph->ip_off = 0;
    iph->ip_ttl = 64;
    iph->ip_p   = IPPROTO_ICMP;
    iph->ip_sum = 0;
    iph->ip_src.s_addr = src_sin->sin_addr.s_addr;
    iph->ip_dst.s_addr = dst_sin->sin_addr.s_addr;

    // now we compute the checksum for the IP header (albeit this is optional)
    iph->ip_sum = check_sum((unsigned short*) iph, sizeof(struct ip));

    // build ICMP header
    icmph->icmp_type  = htons(0);  // reply
    icmph->icmp_code  = htons(0);
    icmph->icmp_id    = cinfo->icmpinfo.id; 
    icmph->icmp_seq   = cinfo->icmpinfo.seq;
    icmph->icmp_cksum = 0;

    // now we compute the UDP header checksum, across a pseudo message buffer, not the actual UDP header
    unsigned short* buffer = 0;
    unsigned int buffer_size = 
        build_pseudo_hdr(src_sin->sin_addr.s_addr, 
                         dst_sin->sin_addr.s_addr, 
                         IPPROTO_ICMP,
                         (const unsigned char*) icmph,      /* Protocol      */
                         sizeof(struct icmp),               /* Header Size   */
                         msg,                               /* Conetent      */
                         msg_size,                          /* Message Size  */
                         &buffer);                          /* Pseudo Header */

    icmph->icmp_cksum = check_sum(buffer, buffer_size);
    free(buffer);

    // add message data (if any)
    if (msg_size > 0) {
        memcpy(data, msg, msg_size);
    }
    return datagram; 
}     
#endif            


