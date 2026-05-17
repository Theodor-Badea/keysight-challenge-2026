#include "main.h"
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_byteorder.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_random.h>
#include <string.h>

profile_queue my_queues[NUM_PROFILES];

// Min-Heaps separate per port pentru paralelism lockless
static delayed_packet_t delay_heap[NB_PORTS][MAX_HEAP_SIZE];
static int heap_size[NB_PORTS] = {0, 0};

int properties[NUM_PROFILES][4] = {
	{1, 3, 10, 100}, // Q0: HTTP
	{3, 4, 20, 60},  // Q1: HTTPS
	{2, 0, 5, 10},   // Q2: SSH
	{4, 4, 10, 110}, // Q3
	{1, 2, 40, 70},  // Q4
	{0, 1, 40, 60},  // Q5
	{2, 5, 50, 80},  // Q6
	{5, 4, 40, 70},  // Q7
	{7, 2, 20, 60},  // Q8
	{6, 3, 10, 80},  // Q9 DNS
};

void init_queues(void) {
	memset(my_queues, 0, sizeof(my_queues));
	for (int i = 0; i < NUM_PROFILES; i++) {
		my_queues[i].drop_rate = properties[i][0];
		my_queues[i].dup_rate  = properties[i][1];
		my_queues[i].min_delay = properties[i][2];
		my_queues[i].max_delay = properties[i][3];
	}
}

// --- OPERAȚII MIN-HEAP ---

static void heap_push(uint16_t port_id, struct rte_mbuf *m, uint64_t send_tsc, uint16_t tx_port_id) {
	if (unlikely(heap_size[port_id] >= MAX_HEAP_SIZE)) {
		rte_pktmbuf_free(m); // Heap plin, facem drop fortat ca sa nu crapam
		return;
	}
	
	int i = heap_size[port_id]++;
	while (i > 0) {
		int p = (i - 1) / 2;
		if (delay_heap[port_id][p].send_tsc <= send_tsc) break;
		delay_heap[port_id][i] = delay_heap[port_id][p];
		i = p;
	}
	delay_heap[port_id][i].m = m;
	delay_heap[port_id][i].send_tsc = send_tsc;
	delay_heap[port_id][i].tx_port_id = tx_port_id;
}

int heap_get_size(uint16_t port_id) { return heap_size[port_id]; }

uint64_t heap_peek_time(uint16_t port_id) {
	return (heap_size[port_id] == 0) ? 0 : delay_heap[port_id][0].send_tsc;
}

delayed_packet_t heap_pop(uint16_t port_id) {
	delayed_packet_t res = delay_heap[port_id][0];
	heap_size[port_id]--;
	
	if (heap_size[port_id] > 0) {
		delayed_packet_t last = delay_heap[port_id][heap_size[port_id]];
		int i = 0;
		while (i * 2 + 1 < heap_size[port_id]) {
			int left = i * 2 + 1;
			int right = left + 1;
			int child = left;
			if (right < heap_size[port_id] && delay_heap[port_id][right].send_tsc < delay_heap[port_id][left].send_tsc) {
				child = right;
			}
			if (last.send_tsc <= delay_heap[port_id][child].send_tsc) break;
			delay_heap[port_id][i] = delay_heap[port_id][child];
			i = child;
		}
		delay_heap[port_id][i] = last;
	}
	return res;
}

// --- LOGICA DE PROCESARE ---

int classify_packet(struct rte_mbuf *m) {
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	if (rte_be_to_cpu_16(eth_hdr->ether_type) != RTE_ETHER_TYPE_IPV4) return -1;

	struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
	uint32_t ip_dst = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
	int ip_is_even = (ip_dst % 2 == 0);
	uint8_t proto = ipv4_hdr->next_proto_id;
	uint16_t dst_port = 0;

	if (proto == IPPROTO_TCP) {
		struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)((unsigned char *)ipv4_hdr + sizeof(struct rte_ipv4_hdr));
		dst_port = rte_be_to_cpu_16(tcp_hdr->dst_port);
		if (dst_port == 80) return 0;
		if (dst_port == 443) return 1;
		if (dst_port == 22) return 2;
		if (dst_port == 53) return 9;

		int port_is_even = (dst_port % 2 == 0);
		if (!ip_is_even && !port_is_even) return 6;
		if (ip_is_even && !port_is_even) return 7;
		if (ip_is_even && port_is_even) return 4;
	} else if (proto == IPPROTO_UDP) {
		struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)((unsigned char *)ipv4_hdr + sizeof(struct rte_ipv4_hdr));
		dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);
		int port_is_even = (dst_port % 2 == 0);
		if (!ip_is_even && port_is_even) return 3;
		if (ip_is_even && !port_is_even) return 5;
		if (ip_is_even && port_is_even) return 10; // Q10 conform logicii tale
	}
	return -1;
}

void apply_changes(struct rte_mbuf *m, int queue_id, uint16_t tx_port_id) {
	uint64_t now = rte_rdtsc();
	
	if (queue_id < 0 || queue_id >= NUM_PROFILES) {
		// Daca pachetul nu are profil, il punem in heap sa iasa instant (0 delay)
		heap_push(tx_port_id, m, now, tx_port_id);
		return;
	}

	profile_queue *q = &my_queues[queue_id];
	q->stats.total_received++;
	q->pkt_count++;

	// 1. Logica de DROP
	if (q->drop_rate > 0 && (q->pkt_count % q->drop_rate == 0)) {
		rte_pktmbuf_free(m);
		q->stats.total_dropped++;
		return;
	}

	// 2. Logica de DUP (Duplicare)
	int send_count = 1;
	if (q->dup_rate > 0 && ((q->pkt_count % 10) < q->dup_rate)) {
		send_count = 2;
		q->stats.total_duplicated++;
	}

	// 3. Logica de DELAY (Calculare timestamp + Inserare in Heap)
	for (int i = 0; i < send_count; i++) {
		struct rte_mbuf *pkt_to_buffer = m;
		if (i > 0) {
			rte_mbuf_refcnt_update(m, 1); // Crestem ref count pentru clona
		}

		uint64_t delay_ms = q->min_delay;
		if (q->max_delay > q->min_delay) {
			delay_ms += rte_rand() % (q->max_delay - q->min_delay + 1);
		}

		uint64_t delay_cycles = (delay_ms * rte_get_tsc_hz()) / 1000;
		uint64_t scheduled_send_time = now + delay_cycles;

		heap_push(tx_port_id, pkt_to_buffer, scheduled_send_time, tx_port_id);
		q->stats.total_sent++;
	}
}
