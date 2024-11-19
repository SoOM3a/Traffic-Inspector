#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
/* for print 16 Hex in one line */
#define PRINT_LINE_LEN 16
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)
/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14
/* length of UDP header */
#define SIZE_UDP        8
/* typedef for tcp seq */
typedef u_int tcp_seq;
/* IPv4 value in Eethernet layer */
#define IPv4 8
/* Protocol Types values in IP header layer */
#define TCP 6
#define UDP 17


/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};
/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */

	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src;
	struct in_addr ip_dst;
};
/* TCP header */
struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};
/* UDP protocol header. */
struct sniff_udp {
        u_short uh_sport;               /* source port */
        u_short uh_dport;               /* destination port */
        u_short uh_ulen;                /* udp length */
        u_short uh_sum;                 /* udp checksum */
};
/* Http */
struct sniff_http_req{
u_char * http_method;
struct http_header *headers;
};
struct http_header{
    u_char *name;
    u_char *value;
    struct Header *next;
};
struct connection_stream{
struct in_addr ip_src, ip_dst;
u_long port_src, port_dst;
u_short in, out;
u_int ts, tv;
}connection_streams[256];

u_int hashing_function(struct sniff_ip *ip ,u_short port_src, u_short port_dst)
{
#ifdef __linux__
u_int hash_res = ((size_t)(ip->ip_src.s_addr ) ^
                  (size_t)(ip->ip_dst.s_addr) ^
                  (size_t)(htons(port_src) ) ^
                  (size_t)(htons(port_dst)) ^
                  ((size_t)(ip->ip_p))) & 0x00ff;
#elif _WIN32
u_int hash_res = ((size_t)(ip->ip_src..s_addr ) ^
                  (size_t)(ip->ip_dst.s_addr) ^
                  (size_t)(htons(port_src) ) ^
                  (size_t)(htons(port_dst)) ^
                  ((size_t)(ip->ip_p))) & 0x00ff;
#endif

return hash_res;
}
u_int check_avilablity(u_int indx)
{
    if(connection_streams[indx].port_src == 0)
        return 0;
   return 1;
}
void reset_index_in_hashtable(u_int indx)
{
    struct in_addr temp;
    connection_streams[indx].ip_src = temp;
    connection_streams[indx].ip_dst = temp;
    connection_streams[indx].port_src = 0;
    connection_streams[indx].port_dst = 0;
    connection_streams[indx].in = 0;
    connection_streams[indx].out = 0;
    connection_streams[indx].ts = 0;
    connection_streams[indx].tv = 0;
}
void update_stream_connections(struct sniff_ip *ip ,struct sniff_tcp *tcp, u_int ts, u_int tv)
{
    /* To Do */
    /*
            - Need to handle three way handshak for reset(fin, fin/Ack,Ack)/begin of communication(Syn,Syn/ack,Ack)
            - Need to handle tcp rest flag
    */
    u_int Indx = hashing_function( ip, tcp->th_sport, tcp->th_dport);
    if ((tcp->th_flags & (TH_SYN | TH_ACK)) == TH_SYN) // Create Stream
    {
        if(check_avilablity(Indx))
        {
                 #ifdef __linux__
                    if(ip->ip_src.s_addr == connection_streams[Indx].ip_src.s_addr)
                            connection_streams[Indx].out++ ;
                    else
                            connection_streams[Indx].in++;
                 #elif _WIN32
                    if(ip->ip_src.s_addr == connection_streams[Indx].ip_src.s_addr)
                            connection_streams[Indx].out++ ;
                    else
                            connection_streams[Indx].in++;
                #endif

         return;
        }
        connection_streams[Indx].ip_src = ip->ip_src;
        connection_streams[Indx].ip_dst = ip->ip_dst;
        connection_streams[Indx].port_src = tcp->th_sport;
        connection_streams[Indx].port_dst = tcp->th_dport;
        connection_streams[Indx].in = 0;
        connection_streams[Indx].out = 1;
        connection_streams[Indx].ts = ts;
        connection_streams[Indx].tv = tv;
    }
    else if( (tcp->th_flags & TH_RST ) == TH_RST &&
             (tcp->th_flags & TH_ACK ) == TH_ACK)
    {
        if(!check_avilablity(Indx))
        {
             /* printf("\n==== TCP connection missing SYN(initiation) =====\n"); */
             return;
        }
        /*
                #ifdef __linux__
          if(ip->ip_src.s_addr == connection_streams[Indx].ip_src.s_addr){
                connection_streams[Indx].out++ ;
                connection_streams[Indx].in++ ; // As mandatory to recv Ack as sender, if RST sent as per rfc
                // Need to Handle packet reTransmissions, so we can expect reiving more fin/ack >=1 at least
            }
                 else{
                connection_streams[Indx].in++;
                }
        #elif _WIN32
          if(ip->ip_src.S_un.S_addr == connection_streams[Indx].ip_src.S_un.S_addr){
                connection_streams[Indx].out++ ;
                connection_streams[Indx].in++ ; // As mandatory to recv Ack as sender, if RST sent as per rfc
                // Need to Handle packet reTransmissions, so we can expect reiving more fin/ack >=1 at least
            }
                     else{
                connection_streams[Indx].in++;
                }
        #endif
        */
          if(ip->ip_src.s_addr == connection_streams[Indx].ip_src.s_addr){
                connection_streams[Indx].out++ ;
                connection_streams[Indx].in++ ; // As mandatory to recv Ack as sender, if RST sent as per rfc
                // Need to Handle packet reTransmissions, so we can expect reiving more fin/ack >=1 at least
            }
                 else{
                connection_streams[Indx].in++;
                }


          printf("\n==== Connection Details =====\n");
          printf("SrcIP:%s:%d\n",inet_ntoa(connection_streams[Indx].ip_src),htons(connection_streams[Indx].port_src));
          printf("DstIP:%s:%d\n",inet_ntoa(connection_streams[Indx].ip_dst),htons(connection_streams[Indx].port_dst));
          printf("IN:%d \t OUT:%d\n",connection_streams[Indx].in,connection_streams[Indx].out);
          printf("Duration in second:milisec - %d:%d\n=============================\n\n" , (ts-connection_streams[Indx].ts), (tv-connection_streams[Indx].tv));
          reset_index_in_hashtable(Indx);
    }
    else
    {
       /*
        #ifdef __linux__
            if(ip->ip_src.s_addr == connection_streams[Indx].ip_src.s_addr)
                connection_streams[Indx].out++ ;
            else
                connection_streams[Indx].in++;
        #elif _WIN32
            if(ip->ip_src.S_un.S_addr == connection_streams[Indx].ip_src.S_un.S_addr)
                connection_streams[Indx].out++ ;
            else
                connection_streams[Indx].in++;
        #endif
       */
            if(ip->ip_src.s_addr == connection_streams[Indx].ip_src.s_addr)
                connection_streams[Indx].out++ ;
            else
                connection_streams[Indx].in++;
    }

}
u_int check_exisitence_of_connection_stream (struct sniff_ip *ip ,struct sniff_tcp *tcp)
{
        u_int Indx = hashing_function( ip, tcp->th_sport, tcp->th_dport);

return check_avilablity(Indx);
}
struct sniff_http_req * http_parse_request(char *rawdata, u_int http_sz) {
    struct sniff_http_req *req = NULL;
    req = malloc(sizeof(struct sniff_http_req));
    // Method
    size_t method_len = strcspn(rawdata, " ");
    if (memcmp(rawdata, "GET", strlen("GET")) == 0) {
        req->http_method = "GET";
    } else if (memcmp(rawdata, "POST", strlen("POST")) == 0) {
        req->http_method = "POST";
    } else {
        return NULL;
    }
    http_sz -= method_len;
    if(http_sz <= 0 )
        return;
    rawdata += method_len + 1;  // move past <SPACE>

    // Request-URI
    size_t request_line_sz = strcspn(rawdata, "\n")+1; // move past <LF>

    http_sz -= request_line_sz;
    if(http_sz <= 0 )
        return;
    rawdata += request_line_sz;
    struct http_header *header = NULL, *last = NULL;
    while (rawdata[0]!='\r' || rawdata[1]!='\n') {
        last = header;
        header = malloc(sizeof(struct http_header));
        if (!header) {
            free(req->http_method);
            free(req->headers);
            return NULL;
        }
        // name
        size_t name_len = strcspn(rawdata, ":");
        if (memcmp(rawdata,"Host", strlen("HOST")) == 0 || memcmp(rawdata,"User-Agent", strlen("User-Agent")) == 0)
        {
            header->name = malloc(name_len + 1);
            if (!header->name) {
                free(req->http_method);
                free(req->headers);
                return NULL;
                }
            memcpy(header->name, rawdata, name_len);
            header->name[name_len] = '\0';
            rawdata += name_len + 1; // move past :
        while (*rawdata == ' ') {
            rawdata++;
        }

        // value
        size_t value_len = strcspn(rawdata, "\r\n");
        header->value = malloc(value_len+ 1);
        if (!header->value) {
            free(req->http_method);
            free(req->headers);
            return NULL;
        }
        memcpy(header->value, rawdata, value_len);
        header->value[value_len] = '\0';
        rawdata += value_len + 2; // move past <CR><LF>

        // next
        header->next = last;
      }
      else
        {
            size_t value_len = strcspn(rawdata, "\r\n");
            if (value_len ==0)
            {
            free(header);
            header = last;
            break;
            }
            rawdata += value_len + 2;
            free(header);
            header = last;
            continue;
        }

    }
    req->headers = header;
    return req;
}

struct http_header * http_add_missing_from_tcp_segments(u_char *rawdata)
{
    struct http_header *header = NULL, *last = NULL;
    while (rawdata[0]!='\r' || rawdata[1]!='\n') {
        last = header;
        header = malloc(sizeof(struct http_header));
        if (!header) {
            free(header);
            return NULL;
        }
        // name
        size_t name_len = strcspn(rawdata, ":");
        if (memcmp(rawdata,"Host", strlen("HOST")) == 0 || memcmp(rawdata,"User-Agent", strlen("User-Agent")) == 0)
        {
            header->name = malloc(name_len + 1);
            if (!header->name) {
                free(header);
                return NULL;
                }
            memcpy(header->name, rawdata, name_len);
            header->name[name_len] = '\0';
            rawdata += name_len + 1; // move past :
        while (*rawdata == ' ') {
            rawdata++;
        }

        // value
        size_t value_len = strcspn(rawdata, "\r\n");
        header->value = malloc(value_len+ 1);
        if (!header->value) {
            free(header);
            return NULL;
        }
        memcpy(header->value, rawdata, value_len);
        header->value[value_len] = '\0';
        rawdata += value_len + 2; // move past <CR><LF>

        // next
        header->next = last;
      }
      else
        {
            size_t value_len = strcspn(rawdata, "\r\n");
            if (value_len)
            {
            free(header);
            header = last;
            break;
            }
            rawdata += value_len + 2;
            free(header);
            header = last;
            continue;
        }

    }
   return header;
}

