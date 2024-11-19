#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>
#include "parser_handler.h"
#include "pthred_queue.h"

void dispatcher_handler(struct Parser *parser, const struct pcap_pkthdr *, const u_char *);
struct pthread_queue *pth_queue;
/*char * dummy_offline[] = {"C:\\Users\\abdel\\Downloads\\http_parser\\http_parser\\bin\\http.exe",
            "-offline", "C:\\Users\\abdel\\Downloads\\http_parser\\http_parser\\bin\\Debug\\tcptrans.pcap",
            "output.txt"}; */
//Wi-Fi
/*char * dummy_offline[] = {"C:\\Users\\abdel\\Downloads\\http_parser\\http_parser\\bin\\http.exe",
            "-online", "\\Device\\NPF_{6BE42996-5173-4E93-99DC-52700C6C24D2}",
            "output.txt"};
//\\Device\\NPF_{6BE42996-5173-4E93-99DC-52700C6C24D2}
*/
void show_interfaces()
{
        pcap_if_t *alldevsp;       /* list of interfaces */
        char errbuf[PCAP_ERRBUF_SIZE];
        int i = 0;
        if (pcap_findalldevs (&alldevsp, errbuf) < 0)
          {
            fprintf (stderr, "%s", errbuf);
            exit (1);
          }

        while (alldevsp != NULL)
          {
            printf ("%d- %s\n",++i,alldevsp->name);
            alldevsp = alldevsp->next;
          }
}
int main(int argc, char **argv)
{



	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	//argc = 3;
	//argv = dummy_offline;
	if(argc < 3 )
	{
		printf("usage: %s -offline pcap_path outputfile\n", argv[0]);
		printf("usage: %s -online interfcaeID outputfile\n", argv[0]);

		return -1;

	}
    /* Open the capture file */
    if(strcmp(argv[1] , "-offline") == 0)
     {
            remove(argv[3]);
            if ((fp = pcap_open_offline(argv[2],errbuf)) == NULL)
            {
                fprintf(stderr,"\nUnable to open the file %s.\n", argv[2]);
                return -1;
            }
    }
    /* Open live */
    else if(strcmp(argv[1] , "-online") == 0)
     {
            remove(argv[3]);
            if ((fp = pcap_open_live(argv[2], BUFSIZ, 1, 1000, errbuf))== NULL) {
                fprintf(stderr, "Couldn't open device %s: %s\n", argv[2], errbuf);
                show_interfaces();
                return(2);
            }
     }
     else
        printf("Please Enter valid arguments\n");
    struct Parser *parser= create_parser(argv[3]);
    pth_queue = create_pthread_Queue();

	/* read and dispatch packets until EOF is reached */
	pcap_loop(fp, 0, dispatcher_handler, parser);
   struct pthread_node * write_th;
 //  printf("====== pacp loop done ======\n");

   while(!pthqueue_empty(pth_queue))
    {
       write_th =  pth_POP(pth_queue);;
       pthread_join(write_th->packet_write_thread_id, NULL);

       free(write_th);
    }
	pcap_close(fp);


	destroy_parser(parser);
	return 0;
}



void dispatcher_handler(struct Parser *parser,
						const struct pcap_pkthdr *header,
						const u_char *pkt_data)
{
//printf("Packet Recived!!!!\n");
push(parser->packet_queue,pkt_data,header);

struct pthread_node * new_pth_write = pthread_create_node();
pth_push(pth_queue, new_pth_write);
pthread_create(&(new_pth_write->packet_write_thread_id), NULL, writer_handler, parser);
// sleep(1); Check if Multithreading works by sleep main thread
}
