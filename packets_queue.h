# include <stdlib.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include "tcp_udp_packet.h"
struct Queue_packet
{
int Queue_size;
struct packet_node *head;
struct packet_node *tail;
};
pthread_mutex_t lock_push;

struct packet_node
{
  u_char *pkt_data;
  char packet_type;
   struct sniff_ethernet *ethernet; /* The ethernet header */
   struct sniff_ip *ip; /* The IP header */
   struct sniff_tcp *tcp; /* The TCP header */
   struct sniff_udp *udp; /* The TCP header */
  struct pcap_pkthdr *header;
  struct packet_node *next;
  struct sniff_http_req * http_req;
  u_int size_ip;
  u_int size_tcp; /* Packet we looking for either TCP */
  const char *payload; /* Packet payload */
  u_int payload_size ;
};

struct packet_node* packet_node_insert(u_char *pkt_data,  struct pcap_pkthdr *header)
{
    struct packet_node* temp = (struct packet_node*)malloc(sizeof(struct packet_node));

    temp->pkt_data =  malloc(header->caplen);
    memcpy(temp->pkt_data, pkt_data,header->caplen);
    temp->next = NULL;
    temp->http_req = NULL;
    temp->header = (struct pcap_pkthdr*)malloc(sizeof(struct pcap_pkthdr));
    memcpy(temp->header, header, sizeof(struct pcap_pkthdr));
    temp->ethernet = (struct sniff_ethernet*)(temp->pkt_data);
    if(temp->ethernet->ether_type != IPv4)
    {
        free(temp);
        return NULL;
    }
    temp->ip = (struct sniff_ip*)(temp->pkt_data + SIZE_ETHERNET);
    temp->size_ip = IP_HL(temp->ip)*4;
    if (temp->size_ip < 20) {
       // printf("   * Invalid IP header length: %u bytes\n", temp->size_ip);
        free(temp);
        return NULL;
    }
    if(temp->ip->ip_p == TCP)
    {
        temp->tcp = (struct sniff_tcp*)(temp->pkt_data + SIZE_ETHERNET + temp->size_ip);
        temp->size_tcp = TH_OFF(temp->tcp) * 4;
        if (temp->size_tcp < 20) {
         // printf("   * Invalid TCP header length: %u bytes\n", temp->size_tcp);
        free(temp);
        return NULL;
        }
        temp->packet_type = 'T';
        temp->payload_size = (temp->header->caplen - (SIZE_ETHERNET + temp->size_ip + temp->size_tcp)) ;
        temp->payload = (u_char *)(temp->pkt_data + SIZE_ETHERNET + temp->size_ip + temp->size_tcp);
        if ( temp->payload_size > 0)
          if (memcmp(temp->payload, "GET", strlen("GET"))==0)
               temp->http_req = http_parse_request(temp->payload,temp->payload_size);
          else if(memcmp(temp->payload, "POST", strlen("POST"))==0)
               temp->http_req = http_parse_request(temp->payload,temp->payload_size);
          else if (check_exisitence_of_connection_stream(temp->tcp, temp->ip) && temp->http_req != NULL)
          {
               struct http_header *new_headers=http_add_missing_from_tcp_segments(temp->payload);
          }
        //Message = "*****TCP Packet****";
    }
    else if(temp->ip->ip_p == UDP)
    {
        temp->udp = (struct sniff_udp*)(temp->pkt_data + SIZE_ETHERNET + temp->size_ip);
        temp->payload_size = ntohs(temp->ip->ip_len) - (temp->size_ip + SIZE_UDP);
         if (temp->payload_size > ntohs(temp->udp->uh_ulen))
                temp->payload_size = ntohs(temp->udp->uh_ulen);
        temp->payload = temp->pkt_data + SIZE_ETHERNET + temp->size_ip + SIZE_UDP;
        temp->packet_type = 'U';
       // printf("   *****UDP Packet****\n" );
    }
    else
    {
        free(temp);
       return NULL;
    }
    return temp;
}
struct Queue_packet* createQueue()
{
    struct Queue_packet* temp_queue = (struct Queue_packet*)malloc(sizeof(struct Queue_packet));
    temp_queue->head = temp_queue->tail = NULL;
    temp_queue->Queue_size = 0;
    pthread_mutex_init(&(lock_push), NULL);
    return temp_queue;
}


int queue_empty(struct Queue_packet *packet_queue)
{
    if((packet_queue->head == packet_queue->tail) && packet_queue->head == NULL)
    {
        return 1;
    }
return 0;
}
void push(struct Queue_packet *packet_queue, u_char * pkt_data,struct pcap_pkthdr *header )
{
    // Create packet Node
    struct packet_node* temp = packet_node_insert(pkt_data , header);
    if(temp == NULL)
        return;
     if(temp->packet_type == 'T')
        {
         // printf("time is sec: %d usec:%d\n" , sizeof(header->ts.tv_sec) , sizeof(header->ts.tv_usec) );
       //   hashing_function( temp->ip, temp->tcp->th_sport,temp->tcp->th_dport );
       update_stream_connections(temp->ip, temp->tcp, header->ts.tv_sec, header->ts.tv_usec);

        }

    // /If queue is empty, then new node is Head and Tail
    if (packet_queue->tail == NULL)
        {
            packet_queue->head = packet_queue->tail = temp;
            packet_queue->Queue_size = 1;
            return;
        }

    // Add the new node at the end of queue and change tail
    packet_queue->tail->next = temp;
    packet_queue->tail = temp;
    packet_queue->Queue_size++;
}

struct packet_node * POP(struct Queue_packet *packet_queue)
{
struct packet_node*  data_temp = NULL;
    if(!queue_empty(packet_queue))
    {
  // If queue is not empty.
    data_temp = packet_queue->head;
    packet_queue->head = packet_queue->head->next;


    // If front becomes NULL, then change rear also as NULL
    if (packet_queue->head == NULL)
       packet_queue->tail = NULL;

    packet_queue->Queue_size--;
    }
 return data_temp;
}


