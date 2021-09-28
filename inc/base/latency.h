/* 
 * Netperf Utilities for calculating packet latencies on the client side.
 * */
#pragma once
/****************************************************************/
// CONSTANTS
#define MAX_ITERATIONS 10000000
#define MAX_PACKETS   10
#define MAX_SEGMENT_SIZE 8192

#define rate_gbps(rate_pps, size) ((float)rate_pps * (float)(size) * 8.0 / (float)1e9)
/****************************************************************/

typedef struct Packet_Map_t
{
    uint64_t rtts[MAX_ITERATIONS * MAX_PACKETS];
    uint64_t ids[MAX_ITERATIONS * MAX_PACKETS]; // unique IDs sent in each packet
    size_t total_count;
    uint32_t *sent_ids;
    uint64_t *grouped_rtts;
} Packet_Map_t;

typedef struct Latency_Dist_t
{
    uint64_t min, max;
    uint64_t latency_sum;
    uint64_t total_count;
    float moving_avg;
    uint64_t latencies[MAX_ITERATIONS];
} Latency_Dist_t;

int calculate_total_packets_required(uint32_t seg_size, uint32_t nb_segs);

int calculate_and_dump_latencies(Packet_Map_t *packet_map, 
                                    Latency_Dist_t *latency_dist, 
                                    size_t num_sent, 
                                    int num_packets_per_request,
                                    uint64_t total_time,
                                    size_t packet_size,
                                    size_t rate_pps,
                                    int has_latency_log,
                                    char *latency_log,
                                    int in_cycles);

int cmpfunc(const void *a, const void *b);

int add_latency_to_map(Packet_Map_t *map, uint64_t rtt, uint32_t id);

void free_pktmap(Packet_Map_t *map);

int calculate_latencies(Packet_Map_t *map, 
                            Latency_Dist_t *dist, 
                            size_t num_sent, 
                            size_t num_per_bucket);

int add_latency(Latency_Dist_t *dist, uint64_t latency);

uint64_t display(uint64_t num, int in_cycles);

int dump_latencies(Latency_Dist_t *dist,
                        uint64_t total_time,
                        size_t message_size,
                        float rate_gbps,
                        int has_latency_log,
                        char *latency_log,
                        int in_cycles);

