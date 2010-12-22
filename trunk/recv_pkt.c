/*
 * Web Rebinding
 *
 * Redirect all the DNS/IMCP/HTTP requests of LAN PC to the Gateway
 *
 * Author: Chad Sheu
 * Last Modify: 2010/12/09
 */

#include "web_rebinding.h"

static char* get_dns_domain(char *dns_packet, int packet_size);
static int get_dns_info(char* pkt_buffer, int nrecv, struct conn_info *cinfo);
    
#if ENABLE_HTTP_REPLY == 1
static int get_http_info(char* pkt_buffer, int nrecv, struct conn_info *cinfo);
static int find_http_pattern(const char *data, size_t dlen, const char *pattern, 
             size_t plen, char term, unsigned int *numoff, unsigned int *numlen);
#endif

int get_conn_info (int nrecv, char *pkt_buffer, struct conn_info *cinfo)
{
    int ret = UNKNOWN_REQUEST;
    unsigned char* iphead = pkt_buffer + 14;  
    snprintf(cinfo->src_ip, 16, "%d.%d.%d.%d\0", iphead[12], iphead[13], iphead[14], iphead[15]);
    snprintf(cinfo->dst_ip, 16, "%d.%d.%d.%d\0", iphead[16], iphead[17], iphead[18], iphead[19]);
    cinfo->protocol = (int)(iphead[9]);
        
    ddebug("%s --(%d)--> %s", cinfo->src_ip, cinfo->protocol, cinfo->dst_ip);

    if(cinfo->protocol == 17){ // UDP
        cinfo->src_port = (int)((iphead[20]<<8)+iphead[21]);
        cinfo->dst_port = (int)((iphead[22]<<8)+iphead[23]);
        ddebug(", %d -> %d\n", cinfo->src_port, cinfo->dst_port);

        if(cinfo->dst_port == 53) { // DNS request
            //Handle UDP/DNS
            ret = get_dns_info(pkt_buffer, nrecv, cinfo);
        }
    }  
    else if(cinfo->protocol == 1){ // ICMP
        #if ENABLE_ICMP_REPLY == 1
            cinfo->icmpinfo.id  = (uint16_t)((iphead[24]<<8)+iphead[25]);
            cinfo->icmpinfo.seq = (uint16_t)((iphead[26]<<8)+iphead[27]);
            ret = ICMP_REQUEST; 
        #endif
    }
    else if(cinfo->protocol == 6) { // TCP
        cinfo->src_port = (int)((iphead[20]<<8)+iphead[21]);
        cinfo->dst_port = (int)((iphead[22]<<8)+iphead[23]);
        ddebug(", %d -> %d\n", cinfo->src_port, cinfo->dst_port);

        if(cinfo->dst_port == 80) { // HTTP
            //Handle TCP
            unsigned char* tcphead = iphead + 20;
            cinfo->tcpinfo.tcp_len = nrecv - 14 - 20 - 20;
            cinfo->tcpinfo.seq = ((tcphead[4]<<24)|(tcphead[5]<<16)|(tcphead[6]<<8) |tcphead[7]);
            cinfo->tcpinfo.ack = ((tcphead[8]<<24)|(tcphead[9]<<16)|(tcphead[10]<<8)|tcphead[11]);

            #if ENABLE_SYN_ACK_REPLY == 1 || ENABLE_HTTP_REPLY == 1
                //Handle TCP SYN
                if(tcphead[13] == 0x02) {
                    ret = SYN_REQUEST;
                }
                else {
                    ret = get_http_info(pkt_buffer, nrecv, cinfo);
                }
            #endif   
        }
    }

    ddebug("\n");
    return ret;
}

#if ENABLE_HTTP_REPLY == 1
/* Return 1 for match, 0 for accept, -1 for partial. */
static int find_http_pattern(const char *data, size_t dlen, const char *pattern, 
             size_t plen, char term, unsigned int *numoff, unsigned int *numlen)
{
    size_t i, j, k;
    int state = 0;
    *numoff = *numlen = 0;

    ddebug("%s: pattern = '%s', dlen = %u\n",__FUNCTION__, pattern, dlen);
    if (dlen == 0) {
        return 0;
    }
                         
    /* Short packet: try for partial? */
    if (dlen <= plen) {	
        if (strncmp(data, pattern, dlen) == 0)
            return -1;
        else 
            return 0;
    }

    for (i = 0; i <= (dlen - plen); i++) {
        /* DFA : \r\n\r\n :: 1234 */
        if (*(data + i) == '\r') {
            if (!(state % 2)) 
                ++state;	    /* forwarding move */
            else 
                state = 0;		/* reset */
        }
        else if (*(data + i) == '\n') {
            if (state % 2) 
                ++state;
            else 
                state = 0;
        }
        else 
            state = 0;

        if (state >= 4)
            break;

        /* pattern compare */
        if (memcmp(data + i, pattern, plen ) != 0)
            continue;

        /* Here, it means patten match!! */
        *numoff=i + plen;
        for (j = *numoff, k = 0; data[j] != term; j++, k++)
            if (j > dlen) 
                return -1 ;	/* no terminal char */

        *numlen = k;
        return 1;
    }
    return 0;
}
#endif

#if ENABLE_HTTP_REPLY == 1
static int get_http_info(char* pkt_buffer, int nrecv, struct conn_info *cinfo)
{
    unsigned char* data = pkt_buffer + 14 + 20 + 20;
    unsigned int datalen = nrecv - 14 - 20 - 20;
    /* Basic checking, is it HTTP packet? */
    if (datalen < 10) {
        return UNKNOWN_REQUEST; /* Not enough length, ignore it */
    }

    if (memcmp(data, "GET ", sizeof("GET ") - 1) != 0 &&
        memcmp(data, "POST ", sizeof("POST ") - 1) != 0 &&
        memcmp(data, "HEAD ", sizeof("HEAD ") - 1) != 0) {
        return UNKNOWN_REQUEST;  /* Pass it */	
    }

    int found, offset;
    int hostlen, pathlen; 
    /* find the 'Host: ' value for URL and HOST filter */
    found = find_http_pattern(data, datalen, "Host: ", sizeof("Host: ") - 1, '\r', &offset, &hostlen);
    ddebug("Host found=%d\n", found);
    if (!found || !hostlen) {
        return UNKNOWN_REQUEST;         
    }

    char host[128];
    hostlen = (hostlen < PKT_BUF_LEN) ? hostlen : PKT_BUF_LEN;
    strncpy(host, data + offset, hostlen);
    *(host + hostlen) = 0;		/* null-terminated */
    ddebug("HOST=%s, hostlen=%d\n", host, hostlen);  

    return HTTP_REQUEST;         
}   
#endif

/* Extract the domain name from the DNS query packet */
static char *get_dns_domain(char *dns_packet, int packet_size)
{
	char *domain_name_pointer = NULL;
	char *domain_name = NULL;    
	char *tmp_ptr = NULL;
	int dns_header_len = sizeof(struct dns_header);
	int name_part_len = 0;
	int dn_len = 0;

	if(packet_size > dns_header_len){
		domain_name_pointer = (dns_packet + dns_header_len);
		
		do {
			/* Get the length of the next part of the domain name */
			name_part_len = (int) domain_name_pointer[0];

			/* If the length is zero or invalid, then stop processing the domain name */
			if((name_part_len <= 0) || (name_part_len > (packet_size-dns_header_len))){
				break;
			}
			domain_name_pointer++;

			/* Reallocate domain_name pointer to name_part_len plus two bytes;
			 * one byte for the period, and one more for the trailing NULL byte.
			 */
			tmp_ptr = domain_name;
			domain_name = realloc(domain_name,(dn_len+name_part_len+PERIOD_SIZE+1));
			if(domain_name == NULL){
				if(tmp_ptr) free(tmp_ptr);
				perror("Realloc Failure");
				return NULL;
			}
			memset(domain_name+dn_len,0,name_part_len+PERIOD_SIZE+1);

			/* Concatenate this part of the domain name, plus the period */
			strncat(domain_name,domain_name_pointer,name_part_len);
			strncat(domain_name,PERIOD,PERIOD_SIZE);

			/* Keep track of how big domain_name is, and point 
			 * domain_name_pointer to the next part of the domain name.
			 */
			dn_len += name_part_len + PERIOD_SIZE + 1;
			domain_name_pointer += name_part_len;
		} while(name_part_len > 0);
	}

	return domain_name;
} 

static int get_dns_info(char* pkt_buffer, int nrecv, struct conn_info *cinfo)
{
    /* Process DNS request packets */
    int packet_size = nrecv - 14 - 20 - 8;
    if(packet_size <= (int) (sizeof(struct dns_header) + sizeof(struct dns_question_section))){
        error("Received invalid DNS packet; packet size too small\n");
        return UNKNOWN_REQUEST;
    }
		
    char *dns_packet = pkt_buffer + 14 + 20 + 8;
	struct dns_header *header = (struct dns_header *) dns_packet;
    if(ntohs(header->num_questions) != MAX_DNS_QUESTIONS){
        error("DNS packet contained the wrong number of questions\n");
        return UNKNOWN_REQUEST;
    }
    ddebug("DNS pakcet size: %d, Number of questions: %d\n", 
           packet_size, ntohs(header->num_questions));
    
    /* Extract the domain name in a standard string format 
     * Make sure we got a valid domain query string 
     */
    char *domain_name = get_dns_domain(dns_packet, packet_size);
    if(strlen(domain_name) < 0){
        error("Can't find Domain in DNS packet\n");
        return UNKNOWN_REQUEST;
    }
    ddebug("Domain Name in DNS packet %s\n", domain_name);
    snprintf(cinfo->dnsinfo.domain_name, 256, "%s\0", domain_name);

    /* Check to make sure this is a type A or type NS, class IN DNS query */
    struct dns_question_section *query_info = 
            (struct dns_question_section *) ((dns_packet) + 
            sizeof(struct dns_header) + 
            strlen(domain_name) + 1);

    if(domain_name != NULL){
        free(domain_name);
    }

    if(query_info->class == htons(DNS_CLASS_IN)) {
        ddebug("Domain Class: IN");
        cinfo->dnsinfo.class = query_info->class;
        cinfo->dnsinfo.type = query_info->type;
        if(query_info->type  == htons(DNS_TYPE_A)) {
            ddebug(", type: A\n");   
        }
        else if(query_info->type  == htons(DNS_TYPE_NS)) {
            ddebug(", Type: NS\n");   
        }
        else if(query_info->type  == htons(DNS_TYPE_PTR)) {
            ddebug(", Type: PTR\n");   
        }
        else if(query_info->type  == htons(DNS_TYPE_AAAA)) {
            ddebug(", Type: AAAA\n");   
        }
        else {
            ddebug("\n");   
        }
    } 
	return DNS_REQUEST;
}      

