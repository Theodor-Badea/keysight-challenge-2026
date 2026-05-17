#ifndef main_h
#define main_h

#include <rte_mbuf.h> 

#define NUM_PROFILES 10

// define the strucure for profile queues
typedef struct {
	int drop_rate; // 1 in drop_rate packets will be dropped
	int dup_rate;  // dup_rate packets out of 10 will be duplicated
	int min_delay; // minimum delay applied to packets in ms
	int max_delay; // maximum delay applied to packets in ms
} profile_queue;

// global array
extern profile_queue my_queues[NUM_PROFILES];

// queues.c
void init_queues(void);
int classify_packet(struct rte_mbuf *m);

#endif
