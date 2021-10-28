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

/* Given a received ethernet header, ipv4 header, udp header and request
 * metadata, write into outgoing header*/
int initialize_reverse_request_header(RequestHeader *request_header,
                                        struct eth_hdr *eth,
                                        struct ip_hdr *ipv4,
                                        struct udp_hdr *udp,
                                        size_t payload_size,
                                        uint64_t packet_id) {
    NETPERF_DEBUG("Received header, src ip %u and src port %u, dst ip %u, dst port %u", ntohl(ipv4->saddr), ntohs(udp->src_port), ntohl(ipv4->daddr), ntohs(udp->dst_port));
    struct eth_hdr *outgoing_eth = &request_header->packet_header.eth;
    struct ip_hdr *outgoing_ipv4 = &request_header->packet_header.ipv4;
    struct udp_hdr *outgoing_udp = &request_header->packet_header.udp;
    
    /* Reverse ethernet header */
    ether_addr_copy(&eth->dhost, &outgoing_eth->shost);
    ether_addr_copy(&eth->shost, &outgoing_eth->dhost);
    outgoing_eth->type = htons(ETHTYPE_IP);

    /* Reverse ipv4 header */
    outgoing_ipv4->version_ihl = VERSION_IHL;
    outgoing_ipv4->tos = 0x0;
    outgoing_ipv4->len = htons(sizeof(struct ip_hdr) + sizeof(struct udp_hdr) + payload_size);
    outgoing_ipv4->id = htons(1);
    outgoing_ipv4->off = 0;
    outgoing_ipv4->ttl = 64;
    outgoing_ipv4->proto = IPPROTO_UDP;
    // TODO: write checksum manually?
    outgoing_ipv4->chksum = 0;
    outgoing_ipv4->saddr = ipv4->daddr;
    outgoing_ipv4->daddr = ipv4->saddr;
    //outgoing_ipv4->chksum = get_chksum(ipv4);
    
    /* Reverse udp header */
    outgoing_udp->src_port = udp->dst_port;
    outgoing_udp->dst_port = udp->src_port;
    outgoing_udp->len = htons(sizeof(struct udp_hdr) + payload_size);
    //outgoing_udp->chksum = get_chksum(udp);


    /* Insert back packet id */
    request_header->packet_id = packet_id;
    return 0;
}
                                
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
    ipv4->version_ihl = VERSION_IHL;
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
    ipv4->chksum = get_chksum(ipv4);

    // fill in the udp header
    udp->src_port = htons(src_port);
    udp->dst_port = htons(dst_port);
    udp->len = htons(sizeof(struct udp_hdr) + payload_size);
    udp->chksum = get_chksum(udp);
    
    return 0;
}


int initialize_server_memory(void *memory,
                                size_t segment_size,
                                size_t array_size)
{
    // for every segment_size across the memory, write in the packet header
    if (array_size % segment_size != 0) {
        NETPERF_WARN("Segment size %u not aligned to array size %u", (unsigned)segment_size, (unsigned)array_size);
        return -EINVAL;
    }
    const char* alphabet = "abcdefghijklmnopqrstuvwxyz";

    int current_index = 0;
    for (size_t i = 0; i < array_size / segment_size; i++) {
        char *cur_pointer = get_server_region(memory, i, segment_size);
        memset(cur_pointer, alphabet[current_index], segment_size);
        current_index = (current_index + 1) % 26;
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
        NETPERF_ASSERT(((char *)ptr - (char *)pointers) == POINTER_SIZE * (i - 1), "Ptr not in right place");
        *ptr = indices[i];
    }

    *(get_client_ptr(pointers, len - 1)) = indices[0];
    *pointer_segments = pointers;
    free(indices);
    return 0;
}

uint64_t get_next_cycles_offset(RateDistribution *rate_distribution) {
    uint64_t intersend = time_intersend(rate_distribution->rate_pps);
    return (uint64_t)(cycles_per_ns * (float)intersend);
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
    uint64_t cur_region_idx = 0;
    for (size_t iter = 0; iter < num_requests; iter++) {
        current_req->timestamp_offset = get_next_cycles_offset(rate_distribution);
        current_req->packet_id = (uint64_t)iter;
        for (size_t i = 0; i < num_segments; i++) {
            current_req->segment_offsets[i] = cur_region_idx;
            // get next pointer in chase
            cur_region_idx = get_next_ptr(indices, cur_region_idx);
            /*NETPERF_DEBUG("pkt id: %u, segment: %u, region: %lu",
                    (unsigned)iter,
                    (unsigned)i,
                    cur_region_idx);*/
            NETPERF_ASSERT(cur_region_idx < (array_size / segment_size), "Calculated out of bounds pointer index in chase: %u", (unsigned)cur_region_idx);
        }
        current_req++;
    }

    // free any temporary memory used
    free(indices);
    *client_requests_ptr = client_requests;
    return ret;
}

