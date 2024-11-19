# include <stdio.h>
# include <stdlib.h>
#include <pcap.h>


struct pthread_queue
{
int Queue_size;
struct pthread_node *head;
struct pthread_node *tail;
};

struct pthread_node
{
 pthread_t * packet_write_thread_id;
  pthread_t * next;
};

struct pthread_queue * create_pthread_queue()
{
    struct pthread_queue * pthqueue;
    pthqueue = (struct pthread_queue*)malloc(sizeof(struct pthread_queue));
    pthqueue->head = pthqueue->tail = NULL;
    pthqueue->Queue_size = 0;
return pthqueue;
}



struct pthread_node * pthread_create_node()
{
    struct pthread_node * node = (struct pthread_node*)malloc(sizeof( struct pthread_node));
    node->packet_write_thread_id = NULL;
    node->next = NULL;
    return node;
}
struct pthread_queue* create_pthread_Queue()
{
    struct pthread_queue* temp_queue = (struct pthread_queue*)malloc(sizeof(struct pthread_queue));
    temp_queue->head = temp_queue->tail = NULL;
    temp_queue->Queue_size = 0;
    return temp_queue;
}


int pthqueue_empty(struct pthread_queue *pth_queue)
{
    if((pth_queue->head == pth_queue->tail) && pth_queue->head == NULL)
    {
        return 1;
    }
return 0;
}
void pth_push(struct pthread_queue *pth_queue,struct pthread_node *thread_id)
{
    if (pth_queue->head == NULL)
        {
            pth_queue->head = pth_queue->tail = thread_id;
            pth_queue->Queue_size = 1;
            return;
        }

    // Add the new node at the end of queue and change tail
    pth_queue->tail->next = thread_id;
    pth_queue->tail = thread_id;
    pth_queue->Queue_size++;
}

struct pthread_node * pth_POP(struct pthread_queue *pth_queue)
{
struct pthread_node *  data_temp = NULL;
    if(!pthqueue_empty(pth_queue))
    {
  // If queue is not empty.
    data_temp = pth_queue->head;
    pth_queue->head = pth_queue->head->next;


    // If front becomes NULL, then change rear also as NULL
    if (pth_queue->head == NULL)
       pth_queue->tail = NULL;

    pth_queue->Queue_size--;
    }
 return data_temp;
}


