#include "packets_queue.h"
#include <pthread.h>
#include <stdlib.h>
#ifdef __linux__
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
#elif _WIN32
    #include <winsock2.h>
#endif

struct Parser {
struct Queue_packet *packet_queue;
u_char *path;
FILE *fptr;
};


pthread_mutex_t lock;

struct Parser* create_parser(u_char *path)
{
    struct Parser* parser = (struct Parser*)malloc(sizeof(struct Parser));
    parser->packet_queue = (struct Queue_packet*)malloc(sizeof(struct Queue_packet));
    parser->packet_queue->head = parser->packet_queue->tail = NULL;
    parser->packet_queue->Queue_size = 0;
    parser->path = path;
    parser->fptr = fopen(path,"ab");
    pthread_mutex_init(&(lock), NULL);
    if(parser->fptr == NULL)
   {
      printf("Error make sure that file path is correct!");
      free(parser->packet_queue);
      free(parser->fptr);
      free(parser);
      exit(1);
   }
    return parser;
}

void writer_handler(struct Parser * parser)
{

    pthread_mutex_lock(&lock);
    struct packet_node * packet = POP(parser->packet_queue);
   // printf("Lock for write a packet \n");
        if (packet != NULL)
        {
            fclose(parser->fptr);
            parser->fptr = fopen(parser->path, "ab");
            write_packet(parser->fptr, packet);
            pthread_mutex_unlock(&lock);
     //   printf("Freeeeeeeeee!!! \n");
        free(packet);

      }

    }



void write_packet(FILE *fptr,  struct packet_node * packet)
{

   if(packet->packet_type == 'T'){
      fprintf(fptr,"\n%s\n","==== TCP Packet ====");
      fprintf(fptr, "src_mac: %02X:%02X:%02X:%02X:%02X:%02X\tdst_mac: %02X:%02X:%02X:%02X:%02X:%02X \n",
                    packet->ethernet->ether_shost[0],packet->ethernet->ether_shost[1],
                    packet->ethernet->ether_shost[2],packet->ethernet->ether_shost[3],
                    packet->ethernet->ether_shost[4],packet->ethernet->ether_shost[5],
                    packet->ethernet->ether_dhost[0],packet->ethernet->ether_dhost[1],
                    packet->ethernet->ether_dhost[2],packet->ethernet->ether_dhost[3],
                    packet->ethernet->ether_dhost[4],packet->ethernet->ether_dhost[5]);
      fprintf(fptr, "src_ip: %s:",inet_ntoa(packet->ip->ip_src));
      fprintf(fptr, "%u" , htons(packet->tcp->th_sport));
      fprintf(fptr, "\tdst_ip: %s:", inet_ntoa(packet->ip->ip_dst));
      fprintf(fptr, "%u\n" , htons(packet->tcp->th_dport));
    if(packet->http_req != NULL)
        {
                fprintf(fptr,"> HTTP %s Method\n", packet->http_req->http_method);
                while(packet->http_req->headers != NULL)
                {

                  struct http_header *header =  packet->http_req->headers;
                  fprintf(fptr,"%s:%s\n",packet->http_req->headers->name, packet->http_req->headers->value);
                  packet->http_req->headers = packet->http_req->headers->next;
                  free(header);
                }
         }
   }
   else if(packet->packet_type == 'U')
   {
      fprintf(fptr,"%s\n","==== UDP Packet ====");
      fprintf(fptr, "src_mac: %02X:%02X:%02X:%02X:%02X:%02X\t\tdst_mac: %02X:%02X:%02X:%02X:%02X:%02X \n",
                    packet->ethernet->ether_shost[0],packet->ethernet->ether_shost[1],
                    packet->ethernet->ether_shost[2],packet->ethernet->ether_shost[3],
                    packet->ethernet->ether_shost[4],packet->ethernet->ether_shost[5],
                    packet->ethernet->ether_dhost[0],packet->ethernet->ether_dhost[1],
                    packet->ethernet->ether_dhost[2],packet->ethernet->ether_dhost[3],
                    packet->ethernet->ether_dhost[4],packet->ethernet->ether_dhost[5]);
      fprintf(fptr, "src_ip: %s:",inet_ntoa(packet->ip->ip_src));
      fprintf(fptr,"%u" , htons(packet->udp->uh_sport));
      fprintf(fptr, "\t\tdst_ip: %s:", inet_ntoa(packet->ip->ip_dst));
      fprintf(fptr,"%u\n\n" , htons(packet->udp->uh_dport));
   }

}


void destroy_parser(struct Parser *parser)
{
    fclose(parser->fptr);
    free(parser->packet_queue);
    free(parser);
}

