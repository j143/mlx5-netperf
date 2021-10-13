/* 
 * Netperf Utilities for constructing the workload: setting up pointer chasing,
 * setting up requests on the client side
 * */
#pragma once

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <base/latency.h>
#include <net/ip.h>
#include <net/udp.h>
#include <net/ethernet.h>
/****************************************************************/
// CONSTANTS
#define REQUEST_PADDING 1.20
#define MAX_SCATTERS    32
#define ID_OFF          0
#define SEGLIST_OFFSET     (ID_OFF + 1)

// MACROS
#define POINTER_SIZE (sizeof(uint64_t))
#define get_next_ptr(mem, idx) \
    *(get_client_ptr(mem, idx))
#define get_client_ptr(mem, idx) ((uint64_t *)((char *)mem + ((idx) * POINTER_SIZE)))
#define get_server_region(memory, idx, segment_size) ((void *)((char *)memory + ((idx) * (segment_size))))
#define get_client_req(client_reqs, idx) (ClientRequest *)((char *)client_reqs + (size_t)(idx) * (sizeof(ClientRequest)))
#define read_u64(ptr, offset) *((uint64_t *)((char *)ptr + (offset) * sizeof(uint64_t)))
/****************************************************************/
static inline void seed_rand() {
    srand(time(NULL));
}

typedef enum RateDistributionType {
    UNIFORM = 0,
} RateDistributionType;

typedef struct RateDistribution {
    RateDistributionType type;
    uint64_t rate_pps;
    uint64_t total_time;
} RateDistribution;

typedef struct ClientRequest
{
    uint64_t timestamp_offset; // not sent inside the packet
    uint64_t packet_id;
    uint64_t segment_offsets[32]; // maximum number of segments we'd be asking for (within array_size)
} __attribute__((packed)) ClientRequest;

typedef struct OutgoingHeader
{
    struct eth_hdr eth;
    struct ip_hdr ipv4;
    struct udp_hdr udp;
} __attribute__((packed)) OutgoingHeader;

typedef struct RequestHeader {
    struct OutgoingHeader packet_header;
    uint64_t packet_id;
} __attribute__((packed)) RequestHeader;

inline void print_individual_headers(struct eth_hdr *eth, struct ip_hdr *ipv4, struct udp_hdr *udp) {
    NETPERF_DEBUG("Src eth:  %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8,
               eth->shost.addr[0], 
               eth->shost.addr[1], 
               eth->shost.addr[2],
               eth->shost.addr[3],
               eth->shost.addr[4],
               eth->shost.addr[5]);
    NETPERF_DEBUG("Dst eth:  %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8,
                eth->dhost.addr[0], 
                eth->dhost.addr[1], 
                eth->dhost.addr[2],
                eth->dhost.addr[3],
                eth->dhost.addr[4],
                eth->dhost.addr[5]);
    NETPERF_DEBUG("Src ip: %u, dst ip: %u, src port: %u, dst port: %u",
                    ntohs(ipv4->saddr),
                    ntohs(ipv4->daddr),
                    ntohs(udp->src_port),
                    ntohs(udp->dst_port));

}

inline void print_outgoing_header(OutgoingHeader *packet_header) {
    NETPERF_DEBUG("Src eth:  %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8,
               packet_header->eth.shost.addr[0], 
               packet_header->eth.shost.addr[1], 
               packet_header->eth.shost.addr[2],
               packet_header->eth.shost.addr[3],
               packet_header->eth.shost.addr[4],
               packet_header->eth.shost.addr[5]);
    NETPERF_DEBUG("Dst eth:  %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8,
               packet_header->eth.dhost.addr[0], 
               packet_header->eth.dhost.addr[1], 
               packet_header->eth.dhost.addr[2],
               packet_header->eth.dhost.addr[3],
               packet_header->eth.dhost.addr[4],
               packet_header->eth.dhost.addr[5]);
    NETPERF_DEBUG("Src ip: %u, dst ip: %u, src port: %u, dst port: %u",
                    ntohs(packet_header->ipv4.saddr),
                    ntohs(packet_header->ipv4.daddr),
                    ntohs(packet_header->udp.src_port),
                    ntohs(packet_header->udp.dst_port));
}

inline void print_request_header(RequestHeader *header) {
    print_outgoing_header(&header->packet_header);
    NETPERF_DEBUG("request_id: %lu", header->packet_id);
}


/* Initialize outgoing header based on incoming packet */
int initialize_reverse_request_header(RequestHeader *header,
                                        struct eth_hdr *eth,
                                        struct ip_hdr *ipv4,
                                        struct udp_hdr *udp,
                                        size_t payload_size,
                                        uint64_t packet_id);

/* Initialize these headers with the given data. */
int initialize_outgoing_header(OutgoingHeader *header,
                                struct eth_addr *src_addr,
                                struct eth_addr *dst_addr,
                                uint32_t src_ip,
                                uint32_t dst_ip,
                                uint16_t src_port,
                                uint16_t dst_port,
                                size_t payload_size);

/* Get next send time offset from previous (in cycles) */
uint64_t get_next_cycles_offset(RateDistribution *rate_distribution);

/* Initialize each region of the server memory to start with the given packet
 * headers. */
int initialize_server_memory(void *memory,
                                    size_t segment_size,
                                    size_t array_size);

/* Initialize the client requests (with fake pointer chasing).
 * Return number of requests set on success, errno set on error. */
int initialize_client_requests(ClientRequest **client_requests_ptr,
                                    RateDistribution *rate_distribution,
                                    size_t segment_size,
                                    size_t num_segments,
                                    size_t array_size);

int initialize_pointer_chasing_at_client(uint64_t **pointer_segments,
                                            size_t array_size, 
                                            size_t segment_size);


