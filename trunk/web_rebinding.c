/*
 * Web Rebinding
 *
 * Redirect all the DNS/IMCP/HTTP requests of LAN PC to the Gateway
 *
 * Author: Chad Sheu
 * Last Modify: 2010/12/09
 */ 

#include "web_rebinding.h"

static int init();
static void stop_binding();
static short wanpkt(struct conn_info *cinfo, char router_ip[16], char router_mask[16]);

static int sock;
static struct ifreq ethreq;

int main(int argc, char **argv) 
{
    init();
    if(sock == -1) {
        return 0;
    }

    int fd = open_csman(NULL,0);
    if (fd < 0) {
        perror("Can't Open CSMAN");
        close_csman(fd);
        close(sock);
        return 0;
    }
    
    struct in_addr local_ip;
    read_csman(fd, CSID_C_LOCAL_LANIP, &local_ip, sizeof(struct in_addr), CSM_R_ZERO);
    
    char router_ip[16];
    snprintf(router_ip, 16, "%s\0", inet_ntoa(local_ip));
 
    struct in_addr local_mask;
    read_csman(fd, CSID_C_LOCAL_LANNM, &local_mask, sizeof(struct in_addr), CSM_R_ZERO); 
    
    char router_mask[16];
    snprintf(router_mask, 16, "%s\0", inet_ntoa(local_mask));
    
    char redirect_page[128];
    snprintf(redirect_page, 128, "http://%s/%s\0", inet_ntoa(local_ip), REDIRECT_PAGE); 
    
    int nrecv = 0; 
    short req = UNKNOWN_REQUEST;
    short do_reply = 0;
    char target[16];
    while (1) {   
        /* 
         * Check to see if the packet contains at least 
         * complete Ethernet (14), IP (20) and TCP/UDP (8) headers.
         */
        char pkt_buffer[PKT_BUF_LEN] = {0};
        nrecv = recvfrom(sock, pkt_buffer, PKT_BUF_LEN, 0, NULL, NULL);
        if (nrecv < 34) {
            error("Incomplete packet (errno is %d)\n", errno);
            continue;
        } 

        struct conn_info cinfo;
        req = get_conn_info(nrecv, pkt_buffer, &cinfo);
        if(req == UNKNOWN_REQUEST) {
            continue;
        }
        
        short is_wanpkt = wanpkt(&cinfo, router_ip, router_mask);
        short is_gw = (!strcmp(cinfo.dst_ip, router_ip)) ? 1 : 0;
        //ddebug("wan-pkt %d, gw %d !\n", is_wanpkt, is_gw);

        if(req == DNS_REQUEST) {
            error("Send DNS rebinding for LAN %s:%d\n", 
                   cinfo.src_ip, cinfo.src_port);

            send_dns_reply(pkt_buffer, nrecv, &cinfo, router_ip);
            snprintf(target, 16, "%s\0", cinfo.src_ip);
            do_reply = 1; 
        }    
        
        #if ENABLE_SYN_ACK_REPLY == 1
            if(req == SYN_REQUEST && is_wanpkt) {
                error("Send SYN+ACK for LAN %s:%d\n", 
                       cinfo.src_ip, cinfo.src_port);

                send_syn_ack(&cinfo);
                snprintf(target, 16, "%s\0", cinfo.src_ip);
                do_reply = 1; 
            }   
        #endif

        #if ENABLE_ICMP_REPLY == 1
            if(req == ICMP_REQUEST && is_wanpkt){
                //error("ICMP packet !\n");
                send_icmp_reply(pkt_buffer, nrecv, &cinfo);
            }
        #endif 

        #if ENABLE_HTTP_REPLY == 1
            if(req == HTTP_REQUEST && do_reply) {
                if(!strcmp(cinfo.src_ip, target)) {
                    error("Send HTTP redirect for LAN %s:%d\n", 
                            cinfo.src_ip, cinfo.src_port);
                    
                    send_http_redirect(&cinfo, redirect_page);            
                    do_reply = 0;
                    snprintf(target, 16, "\0");
                }
                ddebug("\n");
            }
        #endif
    } 
    close(sock);
}

static void stop_binding()
{
    system("iptables -D OUTPUT -o br0 -p icmp --icmp-type 3 -j DROP"); 
    ethreq.ifr_flags &= ~IFF_PROMISC;
    if (ioctl(sock, SIOCSIFFLAGS, &ethreq) == -1) {
        perror("ioctl (SIOCGIFCONF) 2");
        goto fail;
    }  

fail:    
    exit(0);    
}

static int init()
{
	FILE *fd = NULL;
	
    //kill the previous process
	if ((fd = fopen(HTTP_RE_PID, "r")) != NULL) {
	    int pid = 0;
		fscanf(fd,"%d",&pid);
		fclose(fd);
        remove(HTTP_RE_PID);
		kill(pid,SIGTERM);
		sleep(1);
	}   

	if ((fd = fopen(HTTP_RE_PID, "w")) != NULL) {
		fprintf(fd,"%d",getpid());
		fclose(fd);
	}

    if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
        perror("socket");
        goto fail;
    }

    /* Set the network card in promiscuos mode */
    strncpy(ethreq.ifr_name, TARGET_IFACE ,IFNAMSIZ);
    if (ioctl(sock,SIOCGIFFLAGS,&ethreq) == -1) {
        perror("ioctl (SIOCGIFCONF) 1");
        goto fail;
    }

    ethreq.ifr_flags |= IFF_PROMISC;
    if (ioctl(sock,SIOCSIFFLAGS,&ethreq) == -1) {
        perror("ioctl (SIOCGIFCONF) 2");
        goto fail;
    }

    //Avid Router sending destination unreachable to LAN
    system("iptables -A OUTPUT -o br0 -p icmp --icmp-type 3 -j DROP"); 

    /*
     *  Trap interrupt (SIGINT)
     */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = &stop_binding;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGKILL, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

end:
    return sock; 

fail:
    close(sock);
    return -1;
}
       
static short wanpkt(struct conn_info *cinfo, char router_ip[16], char router_mask[16])
{
    unsigned int ip[4];
    sscanf(router_ip, "%d.%d.%d.%d\0" ,&ip[0], &ip[1], &ip[2], &ip[3]);
    
    unsigned int mask[4];
    sscanf(router_mask, "%d.%d.%d.%d\0" ,&mask[0], &mask[1], &mask[2], &mask[3]);

    unsigned int ip_[4];
    sscanf(cinfo->dst_ip, "%d.%d.%d.%d\0" ,&ip_[0], &ip_[1], &ip_[2], &ip_[3]);

    //ddebug("%d %d %d %d\n", (ip[0]&mask[0]), (ip[1]&mask[1]), (ip[2]&mask[2]), (ip[3]&mask[3]) );
    //ddebug("%d %d %d %d\n", (ip_[0]&mask[0]), (ip_[1]&mask[1]), (ip_[2]&mask[2]), (ip_[3]&mask[3]));
    if( (ip[0] & mask[0]) == (ip_[0] & mask[0]) &&
        (ip[1] & mask[1]) == (ip_[1] & mask[1]) &&
        (ip[2] & mask[2]) == (ip_[2] & mask[2]) &&
        (ip[3] & mask[3]) == (ip_[3] & mask[3]))
    {
        return 0;
    }
    return 1;
}


