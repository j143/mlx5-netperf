#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>
#include <assert.h>
#include <limits.h>
#include <ctype.h>
#include <getopt.h>
#include <sys/types.h>
#include <unistd.h>

#include <base/debug.h>
#include <base/request.h>
#include <net/ip.h>
#include <netinet/in.h>
#include <net/udp.h>
#include <net/ethernet.h>
#include <base/rte_memcpy.h>
#include <base/time.h>
#include <asm/ops.h>

int initialize_outgoing_header(OutgoingHeader *header,
                                struct eth_addr *src_addr,
                                struct eth_addr *dst_addr,
                                uint32_t src_ip,
                                uint32_t dst_ip,
                                uint16_t src_port,
                                uint16_t dst_port,
                                size_t payload_size)
{
    struct eth_hdr *eth = &header->eth;
    struct ip_hdr *ipv4 = &header->ipv4;
    struct udp_hdr *udp = &header->udp;
    
    // write in the ethernet header
    ether_addr_copy(src_addr, &eth->shost);
    ether_addr_copy(dst_addr, &eth->dhost);
    eth->type = htons(ETHTYPE_IP);

    // write in the ipv4 header
    ipv4->tos = 0x0;
    ipv4->len = htons(sizeof(struct ip_hdr) + sizeof(struct udp_hdr) + payload_size);
    ipv4->id = htons(1);
    ipv4->off = 0;
    ipv4->ttl = 64;
    ipv4->proto = IPPROTO_UDP;
    // TODO: write checksum manually?
    ipv4->chksum = 0;
    ipv4->saddr = htonl(src_ip);
    ipv4->daddr = htonl(dst_ip);

    // fill in the udp header
    udp->src_port = htons(src_port);
    udp->dst_port = htons(dst_port);
    udp->len = htons(sizeof(struct udp_hdr));
    udp->chksum = get_chksum(udp);
    
    return 0;
}


int initialize_server_memory(void *memory,
                                size_t segment_size,
                                size_t array_size,
                                OutgoingHeader *header)
{
    // for every segment_size across the memory, write in the packet header
    if (array_size % segment_size != 0) {
        NETPERF_WARN("Segment size %u not aligned to array size %u", (unsigned)segment_size, (unsigned)array_size);
        return -EINVAL;
    }

    for (size_t i = 0; i < array_size / segment_size; i++) {
        char *cur_pointer = get_server_region(memory, i, segment_size);
        rte_memcpy(cur_pointer, (char *)header, sizeof(OutgoingHeader));
    }

    return 0;
}

int initialize_pointer_chasing_at_client(uint64_t **pointer_segments,
                                            size_t array_size, 
                                            size_t segment_size) {
    if (array_size % segment_size != 0) {
        NETPERF_WARN("Segment size %u not aligned to array size %u", (unsigned)segment_size, (unsigned)array_size);
        return -EINVAL;
    }

    size_t len = (size_t)(array_size / segment_size);
    uint64_t *indices = malloc(sizeof(uint64_t) * len);
    if (indices == NULL) {
        NETPERF_WARN("Failed to allocate indices to initialize pointer chasing.");
        return -ENOMEM;
    }
    
    for (uint64_t i = 0; i < len; i++) {
        indices[i] = i;
    }

    for (uint64_t i = 0; i < len -1; i++) {
        uint64_t j = i + ((uint64_t)rand() % (len - i));
        if (i != j) {
            uint64_t tmp = indices[i];
            indices[i] = indices[j];
            indices[j] = tmp;
        }
    }

    for (uint64_t i = 0; i < len; i++) {
    }
    void *pointers = malloc(sizeof(uint64_t) * len);
    if (pointers == NULL) {
        NETPERF_WARN("Failed to allocate pointers to chase.");
        return -ENOMEM;
    }

    for (size_t i = 1; i < len; i++) {
        uint64_t *ptr = get_client_ptr(pointers, i - 1);
        NETPERF_ASSERT(((char *)ptr - (char *)pointers) == 64 * (i - 1), "Ptr not in right place");
        *ptr = indices[i];
    }

    *(get_client_ptr(pointers, len - 1)) = indices[0];
    *pointer_segments = pointers;
    free(indices);
    return 0;
}

uint64_t get_next_send_time(uint64_t last_send_time, RateDistribution *rate_distribution) {
    // right now: we only support uniform rate distribution
    uint64_t intersend = time_intersend(rate_distribution->rate_pps);
    return intersend + last_send_time;
}

int initialize_client_requests(ClientRequest **client_requests_ptr,
                                    RateDistribution *rate_distribution,
                                    size_t segment_size,
                                    size_t num_segments,
                                    size_t array_size)
{
    int ret = 0;
    // initialize view of "pointer chasing"
    uint64_t *indices = NULL;
    ret = initialize_pointer_chasing_at_client(&indices, array_size, segment_size);
    RETURN_ON_ERR(ret, "Failed to initialize pointer chasing view at client");
    
    struct ClientRequest *client_requests;
    size_t num_requests = (size_t)((float)rate_distribution->total_time * rate_distribution->rate_pps * REQUEST_PADDING) + 1;
    client_requests = malloc(sizeof(struct ClientRequest) * num_requests);
    if (client_requests == NULL) {
        NETPERF_WARN("Failed to malloc client requests array");
        return -ENOMEM;
    }

    struct ClientRequest *current_req = (struct ClientRequest *)client_requests;
    size_t num_segments_within_region = array_size / segment_size;
    uint64_t cur_region_idx = 0;
    uint64_t cur_timestamp = 0;
    for (size_t iter = 0; iter < num_requests; iter++) {
        current_req->timestamp_offset = cur_timestamp;
        current_req->packet_id = (uint64_t)iter;
        for (size_t i = 0; i < num_segments; i++) {
            current_req->segment_offsets[i] = cur_region_idx;
            // get next pointer in chase
            cur_region_idx = get_next_ptr(indices, cur_region_idx);
            NETPERF_ASSERT(cur_region_idx < num_segments_within_region, "Calculated out of bounds pointer index in chase: %u", (unsigned)cur_region_idx);
        }
        // increment to the next time to send a packet
        cur_timestamp = get_next_send_time(cur_timestamp, rate_distribution);
        current_req++;
    }

    // free any temporary memory used
    free(indices);
    *client_requests_ptr = client_requests;
    return ret;
}

