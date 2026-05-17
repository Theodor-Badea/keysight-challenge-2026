#include "main.h"
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_byteorder.h>

// Instanțiem array-ul de profile
profile_queue_t my_queues[NUM_PROFILES];

// Definim proprietățile (am pus valori dummy pt restul ca să nu crape)
int properties[NUM_PROFILES][4] = {
	{1, 3, 10, 100}, // Q0: HTTP
	{3, 4, 20, 60},  // Q1: HTTPS
	{0, 0, 0, 0},    // Q2: SSH
	{0, 0, 0, 0},    // Q3
	{0, 0, 0, 0},    // Q4
	{0, 0, 0, 0},    // Q5
	{0, 0, 0, 0},    // Q6
	{0, 0, 0, 0},    // Q7
	{0, 0, 0, 0},    // Q8
	{0, 0, 0, 0},    // Q9 DNS
};

// Funcția de inițializare
void init_queues(void) {
	for (int i = 0; i < NUM_PROFILES; i++) {
		my_queues[i].drop_rate = properties[i][0];
		my_queues[i].dup_rate  = properties[i][1];
		my_queues[i].min_delay = properties[i][2];
		my_queues[i].max_delay = properties[i][3];
	}
}

// Funcția de clasificare returnează ID-ul cozii (0 - 10)
int classify_packet(struct rte_mbuf *m) {
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	uint16_t src_port = 0, dst_port = 0;
	uint32_t ip_dst;
	int ip_is_even, port_is_even;
	uint8_t proto;

	// Extragem Header-ul Ethernet
	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	// Verificăm dacă e trafic IPv4 (ignorăm IPv6 sau ARP pentru moment)
	if (rte_be_to_cpu_16(eth_hdr->ether_type) != RTE_ETHER_TYPE_IPV4) {
		return -1; // Cod pentru "nu se aplică regulile / drop / coada default"
	}

	// Extragem Header-ul IP (sare peste header-ul de Ethernet)
	ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
	
	// Convertim IP-ul din format de rețea (Big Endian) în format de host
	ip_dst = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
	ip_is_even = (ip_dst % 2 == 0);
	proto = ipv4_hdr->next_proto_id;

	// Extragem Porturile (TCP sau UDP)
	if (proto == IPPROTO_TCP) {
		struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)((unsigned char *)ipv4_hdr + sizeof(struct rte_ipv4_hdr));
		dst_port = rte_be_to_cpu_16(tcp_hdr->dst_port);
		port_is_even = (dst_port % 2 == 0);

		// Profil 0, 1, 2 (Bazate pe porturi cunoscute)
		if (dst_port == 80) return 0;   /* HTTP */
		if (dst_port == 443) return 1;  /* HTTPS */
		if (dst_port == 22) return 2;   /* SSH */
		if (dst_port == 53) return 9;	/* DNS */

		// Regulile pentru TCP din cerințele tale
		if (!ip_is_even && !port_is_even) return 6; // Q6: IP impar, TCP, Port impar
		if (ip_is_even && !port_is_even) return 7;  // Q7: IP par, TCP, Port impar 
		if (ip_is_even && port_is_even) return 4;   // Q4: IP par, TCP, Port par

	} else if (proto == IPPROTO_UDP) {
		struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)((unsigned char *)ipv4_hdr + sizeof(struct rte_ipv4_hdr));
		dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);
		port_is_even = (dst_port % 2 == 0);

		// Regulile pentru UDP din cerințele tale
		if (!ip_is_even && port_is_even) return 3;  // Q3: IP impar, UDP, Port par
		if (ip_is_even && !port_is_even) return 5;  // Q5 & Q8: IP par, UDP, Port impar 
		if (ip_is_even && port_is_even) return 10;  // Q8: IP par, UDP, Port par
	}

	return -1; // Default
}

void apply_changes(packet) {

}
