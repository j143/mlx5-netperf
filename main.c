#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <net/ethernet.h>
#include <net/ip.h>
#include <net/udp.h>
#include <netinet/in.h>

#include <asm/ops.h>
#include <base/debug.h>
#include <base/time.h>
#include <base/parse.h>
#include <base/mem.h>
#include <base/request.h>
#include <base/latency.h>
#include <base/compiler.h>
#include <base/mempool.h>
#include <base/mbuf.h>
#include <base/page.h>
#include <base/pci.h>
#include <base/stddef.h>
#include <base/atomic.h>
#include <util/udma_barrier.h>
#include <util/mmio.h>
#include <mlx5.h>
#include <mlx5_ifc.h>
#include <mlx5_init.h>
#include <mlx5_rxtx.h>
#include <infiniband/verbs.h>
#include <infiniband/mlx5dv.h>
#include <base/latency.h>

/**********************************************************************/
// CONSTANTS
/**********************************************************************/
#define FULL_PROTO_HEADER 42
#define PKT_ID_SIZE 0
#define FULL_HEADER_SIZE (FULL_PROTO_HEADER + PKT_ID_SIZE)
/**********************************************************************/
// STATIC STATE
static uint8_t mode;
static struct eth_addr server_mac;
static struct eth_addr client_mac;
static uint32_t server_ip;
static uint32_t client_ip;
static uint32_t server_port = 54321; 
static uint32_t client_port = 54321;
static size_t num_segments = 1;
static size_t segment_size = 1024;
static size_t working_set_size = 16384;
static int zero_copy = 0;
static int client_specified = 0;
static int has_latency_log = 0;
static char *latency_log;
static RateDistribution rate_distribution = {.type = UNIFORM, .rate_pps = 5000, .total_time = 2};
static ClientRequest *client_requests = NULL; // pointer to client request information
static OutgoingHeader header = {}; // header to copy in to the request
static Latency_Dist_t latency_dist = { .min = LONG_MAX, .max = 0, .total_count = 0, .latency_sum = 0 };
static Packet_Map_t packet_map = {.total_count = 0, .grouped_rtts = NULL, .sent_ids = NULL };

static void *server_working_set;
static struct mlx5_rxq rxqs[NUM_QUEUES];
static struct mlx5_txq txqs[NUM_QUEUES];
static struct ibv_context *context;
static struct ibv_pd *pd;
static struct ibv_mr *tx_mr;
static struct ibv_mr *rx_mr;
static struct pci_addr nic_pci_addr;
static size_t max_inline_data = 256;

// extern (declared in mlx5_rxtx.h)
struct mempool rx_buf_mempool = {};
struct mempool tx_buf_mempool = {};
struct mempool mbuf_mempool = {};
uint32_t total_dropped = 0;

/**********************************************************************/
static int parse_args(int argc, char *argv[]) {
    // have mode and pci address
    int opt = 0;
    long tmp;

    static struct option long_options[] = {
        {"mode",      required_argument,       0,  'm' },
        {"pci_addr",  required_argument,       0, 'w'},
        {"client_mac", required_argument, 0, 'c'},
        {"server_mac", required_argument, 0, 'e'},
        {"client_ip", required_argument, 0, 'i'},
        {"server_ip", required_argument, 0, 's'},
        {"num_segments", optional_argument, 0, 'k'},
        {"segment_size", optional_argument, 0, 'q'},
        {"rate", optional_argument, 0, 'r'},
        {"time", optional_argument, 0, 't'},
        {"array_size", optional_argument, 0, 'a'},
        {"latency_log", optional_argument, 0, 'l'},
        {"zero_copy", no_argument, 0, 'z'},
        {0,           0,                 0,  0   }
    };
    int long_index = 0;
    int ret;
    while ((opt = getopt_long(argc, argv, "m:w:c:e:i:s:k:q:a:z:r:t:l:",
                              long_options, &long_index )) != -1) {
        switch (opt) {
            case 'm':
                if (!strcmp(optarg, "CLIENT")) {
                    mode = UDP_CLIENT;
                } else if (!strcmp(optarg, "SERVER")) {
                    mode = UDP_SERVER;
                } else {
                    NETPERF_ERROR("Passed in invalid mode: %s", optarg);
                    return -EINVAL;
                }
                break;
            case 'w':
                ret = pci_str_to_addr(optarg, &nic_pci_addr);
                if (ret) {
                    NETPERF_ERROR("Could not parse pci addr: %s", optarg);
                    return -EINVAL;
                }
                break;
            case 'c':
                if (str_to_mac(optarg, &client_mac) != 0) {
                   NETPERF_ERROR("failed to convert %s to a mac address", optarg);
                   return -EINVAL;
                }
                client_specified = 1;
                NETPERF_INFO("Parsed client eth addr: %s", optarg);
                break;
            case 'e':
                if (str_to_mac(optarg, &server_mac) != 0) {
                   NETPERF_ERROR("failed to convert %s to a mac address", optarg);
                   return -EINVAL;
                }
                NETPERF_INFO("Parsed server eth addr: %s", optarg);
                break;
            case 'i':
                if (str_to_ip(optarg, &client_ip) != 0) {
                    NETPERF_ERROR("Failed to parse %s as an IP addr", optarg);
                    return -EINVAL;
                }
                break;
            case 's':
                if (str_to_ip(optarg, &server_ip) != 0) {
                    NETPERF_ERROR("Failed to parse %s as an IP addr", optarg);
                    return -EINVAL;
                }
                break;
            case 'k': // num_segments
                str_to_long(optarg, &tmp);
                num_segments = tmp;
                break;
            case 'q': // segment_size
                str_to_long(optarg, &tmp);
                segment_size = tmp;
                break;
            case 'a': // array_size
                str_to_long(optarg, &tmp);
                working_set_size = tmp;
                break;
            case 'z': // zero_copy
                zero_copy = 1;
                break;
            case 'r': // rate
                str_to_long(optarg, &tmp);
                rate_distribution.rate_pps = tmp;
                break;
            case 't': // total_time
                str_to_long(optarg, &tmp);
                rate_distribution.total_time = tmp;
                break;
            case 'l':
                has_latency_log = 1;
                latency_log = (char *)malloc(strlen(optarg));
                strcpy(latency_log, optarg);
                break;
            default:
                NETPERF_WARN("Invalid arguments");
                exit(EXIT_FAILURE);
        }
    }
    return 0;
}

/**
 * Initializes data for the actual workload.
 * On the client side: initializes the client requests and the outgoing header.
 * On the server side: if there is a single client, initializes the server
 * memory region.
 */
int init_workload() {
    int ret = 0;

    if (mode == UDP_CLIENT) {
        // 1 uint64_t per segment
        size_t client_payload_size = sizeof(uint64_t) * ( SEGLIST_OFFSET + num_segments );
        ret = initialize_outgoing_header(&header,
                                    &client_mac,
                                    &server_mac,
                                    client_ip,
                                    server_ip,
                                    client_port,
                                    server_port,
                                    client_payload_size);
        RETURN_ON_ERR(ret, "Failed to initialize outgoing header");
        ret = initialize_client_requests(&client_requests,
                                            &rate_distribution,
                                            segment_size,

                                            num_segments,
                                            working_set_size);
        RETURN_ON_ERR(ret, "Failed to initialize client requests: %s", strerror(-errno));
    } else {
        // num_segments * segment_size
        size_t server_payload_size = ( num_segments * segment_size ) - FULL_HEADER_SIZE;
        if (client_specified) {
            ret = initialize_outgoing_header(&header,
                                                &server_mac,
                                                &client_mac,
                                                server_ip,
                                                client_ip,
                                                server_port,
                                                client_port,
                                                server_payload_size);
            RETURN_ON_ERR(ret, "Failed to initialize server header");
            ret = initialize_server_memory(server_working_set,
                                            segment_size,
                                            working_set_size,
                                            &header);
            RETURN_ON_ERR(ret, "Failed to fill in server memory: %s", strerror(ret));
        }
    }

    return 0;
}

int init_mlx5() {
    int ret = 0;
    
    ret = init_ibv_context(&context, &pd, &nic_pci_addr);
    RETURN_ON_ERR(ret, "Failed to init ibv context: %s", strerror(errno));

    // Alloc memory pool for TX mbuf structs
    ret = mempool_memory_init(&mbuf_mempool,
                                CONTROL_MBUFS_SIZE,
                                CONTROL_MBUFS_PER_PAGE,
                                REQ_MBUFS_PAGES);
    RETURN_ON_ERR(ret, "Failed to init mbuf mempool: %s", strerror(errno));

    if (mode == UDP_CLIENT) {
        // init rx and tx memory mempools
        ret = mempool_memory_init(&tx_buf_mempool,
                                    REQ_MBUFS_SIZE,
                                    REQ_MBUFS_PER_PAGE,
                                    REQ_MBUFS_PAGES);
        RETURN_ON_ERR(ret, "Failed to init tx mempool for client: %s", strerror(errno));

        ret = memory_registration(pd, 
                                    &tx_mr, 
                                    tx_buf_mempool.buf, 
                                    tx_buf_mempool.len, 
                                    IBV_ACCESS_LOCAL_WRITE);
        RETURN_ON_ERR(ret, "Failed to run memory registration for tx buffer for client: %s", strerror(errno));

        ret = mempool_memory_init(&rx_buf_mempool,
                                    DATA_MBUFS_SIZE,
                                    DATA_MBUFS_PER_PAGE,
                                    DATA_MBUFS_PAGES);
        RETURN_ON_ERR(ret, "Failed to int rx mempool for client: %s", strerror(errno));

        ret = memory_registration(pd, 
                                    &rx_mr, 
                                    rx_buf_mempool.buf, 
                                    rx_buf_mempool.len, 
                                    IBV_ACCESS_LOCAL_WRITE);
        RETURN_ON_ERR(ret, "Failed to run memory reg for client rx region: %s", strerror(errno));
    } else {
        ret = server_memory_init(&server_working_set, working_set_size);
        RETURN_ON_ERR(ret, "Failed to init server working set memory");

        /* Recieve packets are request side on the server */
        ret = mempool_memory_init(&rx_buf_mempool,
                                    REQ_MBUFS_SIZE,
                                    REQ_MBUFS_PER_PAGE,
                                    REQ_MBUFS_PAGES);
        RETURN_ON_ERR(ret, "Failed to int rx mempool for server: %s", strerror(errno));

        ret = memory_registration(pd, 
                                    &rx_mr, 
                                    rx_buf_mempool.buf, 
                                    rx_buf_mempool.len, 
                                    IBV_ACCESS_LOCAL_WRITE);
        RETURN_ON_ERR(ret, "Failed to run memory reg for client rx region: %s", strerror(errno));
        if (!zero_copy) {
            // initialize tx buffer memory pool for network packets
            ret = mempool_memory_init(&tx_buf_mempool,
                                       DATA_MBUFS_SIZE,
                                       DATA_MBUFS_PER_PAGE,
                                       DATA_MBUFS_PAGES);
            RETURN_ON_ERR(ret, "Failed to init tx buf mempool on server: %s", strerror(errno));

            ret = memory_registration(pd, 
                                        &tx_mr, 
                                        tx_buf_mempool.buf, 
                                        tx_buf_mempool.len, 
                                        IBV_ACCESS_LOCAL_WRITE);

            RETURN_ON_ERR(ret, "Failed to register tx mempool on server: %s", strerror(errno));
        } else {
            // register the server memory region for zero-copy
            ret = memory_registration(pd, 
                                        &tx_mr,
                                        server_working_set,
                                        working_set_size,
                                        IBV_ACCESS_LOCAL_WRITE);
            RETURN_ON_ERR(ret, "Failed to register memory for server working set: %s", strerror(errno)); 
        }
    }

    // Initialize single rxq attached to the rx mempool
    ret = mlx5_init_rxq(&rxqs[0], &rx_buf_mempool, context, pd, rx_mr);
    RETURN_ON_ERR(ret, "Failed to create rxq: %s", strerror(-ret));

    struct eth_addr *my_eth = &server_mac;
    struct eth_addr *other_eth = &client_mac;
    int hardcode_sender = client_specified;
    if (mode == UDP_CLIENT) {
        my_eth = &client_mac;
        other_eth = &server_mac;
    }

    ret = mlx5_qs_init_flows(&rxqs[0], pd, context, my_eth, other_eth, hardcode_sender);
    RETURN_ON_ERR(ret, "Failed to install queue steering rules");

    // TODO: for a fair comparison later, initialize the tx segments at runtime
    int init_each_tx_segment = 1;
    if (mode == UDP_SERVER && num_segments > 1) {
        init_each_tx_segment = 0;
    }
    ret = mlx5_init_txq(&txqs[0], 
                            pd, 
                            context, 
                            tx_mr, 
                            max_inline_data, 
                            init_each_tx_segment);
    RETURN_ON_ERR(ret, "Failed to initialize tx queue");

    NETPERF_INFO("Finished creating txq and rxq");
    return ret;
}

int check_valid_packet(struct mbuf *mbuf, void **payload_out, uint32_t *payload_len, struct eth_addr *our_eth) {
    //NETPERF_DEBUG("Mbuf addr: %p, mbuf data addr: %p, diff: %lu, mbuf len: %u", mbuf, mbuf->data, (char *)(mbuf->data) - (char *)mbuf, (unsigned)(mbuf_length(mbuf)));
    unsigned char *ptr = mbuf->data;
    struct eth_hdr * const eth = (struct eth_hdr *)ptr;
    ptr += sizeof(struct eth_hdr);
    struct ip_hdr * const ipv4 = (struct ip_hdr *)ptr;
    ptr += sizeof(struct ip_hdr);
    //struct udp_hdr *const udp = (struct udp_hdr *)ptr;
    ptr += sizeof(struct udp_hdr);

    // check if the dest eth hdr is correct
    if (eth_addr_equal(our_eth, &eth->dhost) != 1) {
        NETPERF_DEBUG("Bad MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8,
            eth->dhost.addr[0], eth->dhost.addr[1],
			eth->dhost.addr[2], eth->dhost.addr[3],
			eth->dhost.addr[4], eth->dhost.addr[5]);
        return 0;
    }

    uint16_t eth_type = ntohs(eth->type);
    if (eth_type != ETHTYPE_IP) {
        NETPERF_DEBUG("Bad eth type: %u", (unsigned)eth_type);
        return 0;
    }

    // check IP header
    if (ipv4->proto != IPPROTO_UDP) {
        NETPERF_DEBUG("Bad recv type: %u", (unsigned)ipv4->proto);
    }
    
    //NETPERF_DEBUG("Ipv4 checksum: %u, Ipv4 ttl: %u, udp checksum: %u", (unsigned)(ntohs(ipv4->chksum)), (unsigned)ipv4->ttl, (unsigned)(ntohs(udp->chksum)));

    // TODO: finish checks
    *payload_out = (void *)ptr;
    *payload_len = mbuf_length(mbuf) - FULL_HEADER_SIZE;
    return 1;

}

int do_client() {
    NETPERF_DEBUG("Starting client");
    struct mbuf *recv_pkts[BURST_SIZE];
    struct mbuf *pkt;
    size_t client_payload_size = sizeof(uint64_t) * (num_segments + SEGLIST_OFFSET);
    int total_packets_per_request = calculate_total_packets_required((uint32_t)segment_size, (uint32_t)num_segments);
    
    size_t num_received = 0;
    size_t outstanding = 0;

    uint64_t total_time = rate_distribution.total_time * 1e9;
    uint64_t start_time_offset = nanotime();
    
    // first client request (first packet sent at time 0)
    ClientRequest *current_request = get_client_req(client_requests, 0);

    // main processing loop
    while (nanotime() < (start_time_offset + total_time)) {
        // allocate actual mbuf struct
        pkt = (struct mbuf *)mempool_alloc(&mbuf_mempool);
        if (pkt == NULL) {
            NETPERF_WARN("Error allocating mbuf for req # %u; recved %u", (unsigned)current_request->packet_id, (unsigned)num_received);
            return -ENOMEM;
        }

        // allocate buffer backing the mbuf
        unsigned char *buffer = (unsigned char *)mempool_alloc(&tx_buf_mempool);
        mbuf_init(pkt, buffer, REQ_MBUFS_SIZE, 0);
        
        // frees the backing store back to tx_buf_mempool and the actual struct
        // back to the mbuf_mempool
        pkt->release = tx_completion;

        // copy data into the mbuf
        mbuf_copy(pkt, 
                    (char *)&header, 
                    sizeof(OutgoingHeader), 
                    0);
        mbuf_copy(pkt, 
                    (char *)current_request, 
                    client_payload_size, 
                    sizeof(OutgoingHeader));

        int sent = 0;
        NETPERF_DEBUG("Attempting to transmit packet %u (send time %lu, actual time: %lu), recved %u", (unsigned)current_request->packet_id, current_request->timestamp_offset, (nanotime() - start_time_offset), (unsigned)num_received);
        current_request->timestamp_offset = nanotime() - start_time_offset;
        while (sent != 1) {
            sent = mlx5_transmit_one(pkt, &txqs[0]);
        }
        
        outstanding += total_packets_per_request;
        current_request += 1;

        while (outstanding > 0) {
            int nb_rx = mlx5_gather_rx((struct mbuf **)&recv_pkts, 
                                        32,
                                        &rx_buf_mempool,
                                        &rxqs[0]);
            if (nb_rx == 0) {
                // if time to send the next packet, break
                if (nanotime() >= (current_request->timestamp_offset + start_time_offset)) {
                    break;
                }
                continue;
            }

            // process any received packets
            for (int i = 0; i < nb_rx; i++) {
                void *payload;
                uint32_t payload_len;
                if (check_valid_packet(recv_pkts[i], &payload, &payload_len, &client_mac) != 1) {
                    NETPERF_DEBUG("Received invalid packet back");
                    mbuf_free(recv_pkts[i]);
                    continue;
                }
                NETPERF_ASSERT((payload_len + FULL_HEADER_SIZE) == 
                                    num_segments * segment_size, 
                                    "Expected size: %u; actual size: %u", 
                                    (unsigned)(num_segments * segment_size),
                                    (unsigned)(payload_len + FULL_HEADER_SIZE));

                // read the timestamp
                uint64_t id = read_u64(payload, ID_OFF);

                // query the timestamp based on the ID
                uint64_t timestamp = (get_client_req(client_requests, id))->timestamp_offset;

                uint64_t rtt = nanotime() - start_time_offset - timestamp;
                //NETPERF_INFO("Calculated %lu as rtt for pkt %lu; starting ts %u, now is %lu", rtt, id, (unsigned)timestamp, nanotime() - start_time_offset);
                add_latency_to_map(&packet_map, rtt, id);

                // free back the received packet
                mbuf_free(recv_pkts[i]);
                num_received += 1;
                outstanding--;
            }
        }

        // wait till time to send the next packet
        while ((nanotime() - start_time_offset) < current_request->timestamp_offset) {}
    }

    // dump the packets
    uint64_t total_exp_time = nanotime() - start_time_offset;
    size_t total_sent = (size_t)current_request->packet_id - 1;
    free(client_requests);
    calculate_and_dump_latencies(&packet_map,
                                    &latency_dist,
                                    total_sent,
                                    total_packets_per_request,
                                    total_exp_time,
                                    num_segments * segment_size,
                                    rate_distribution.rate_pps,
                                    has_latency_log,
                                    latency_log);
    return 0;
}

int process_server_request(struct mbuf *request, 
                                void *payload, 
                                size_t payload_len, 
                                int total_packets_required)
{
    uint64_t segments[MAX_SCATTERS];
    struct mbuf *send_mbufs[MAX_PACKETS][MAX_SCATTERS];

    NETPERF_ASSERT((payload_len % sizeof(uint64_t) == 0),
                    "Payload length: %u not divisible by 8.", (unsigned)payload_len);

    // TODO: check this assertion in non-debug mode
    NETPERF_ASSERT(((payload_len - (SEGLIST_OFFSET * sizeof(uint64_t))) / 
                        sizeof(uint64_t)) == num_segments, 
                        "Request segments %u doesn't match server segments %u",
                        (unsigned)(payload_len / sizeof(uint64_t) - 1),
                        (unsigned)num_segments);

    uint64_t id = read_u64(payload, ID_OFF);
    NETPERF_DEBUG("Received packet with id %lu", id);
    
    for (size_t i = 0; i < num_segments; i++) {
        segments[i] = read_u64(payload, i + SEGLIST_OFFSET);
        NETPERF_DEBUG("Segment %u is %u", (unsigned)i, (unsigned)segments[i]);
    }

    size_t payload_left = num_segments * segment_size;
    size_t segment_array_idx = 0;
    for (int pkt_idx = 0; pkt_idx < total_packets_required; pkt_idx++) {
        size_t actual_segment_size = MIN(payload_left, MIN(segment_size, MAX_SEGMENT_SIZE));
        size_t nb_segs_per_packet = (MIN(payload_left, MAX_SEGMENT_SIZE)) / actual_segment_size;
        size_t pkt_len = actual_segment_size * nb_segs_per_packet;
        NETPERF_DEBUG("Pkt %d: seg size %u, nb_segs %u, pkt_len %u", pkt_idx,
                        (unsigned)actual_segment_size, (unsigned)nb_segs_per_packet, (unsigned)pkt_len);

        if (zero_copy) {
            struct mbuf *prev = NULL;
            for (int seg = 0; seg < nb_segs_per_packet; seg++) {
                void *server_memory = get_server_region(server_working_set,
                                                            segments[segment_array_idx],
                                                            segment_size);
                // allocate mbuf 
                send_mbufs[pkt_idx][seg] = (struct mbuf *)mempool_alloc(&mbuf_mempool);

                // set the next buffer pointer for previous mbuf
                if (prev != NULL) {
                    prev->next = send_mbufs[pkt_idx][seg];
                    prev = send_mbufs[pkt_idx][seg];
                }

                // set metadata for this mbuf
                send_mbufs[pkt_idx][seg]->release = zero_copy_tx_completion;
                mbuf_init(send_mbufs[pkt_idx][seg], 
                            (unsigned char *)server_memory,
                            actual_segment_size,
                            0);
                send_mbufs[pkt_idx][seg]->len = actual_segment_size;
                segment_array_idx += 1;
            }
            // for the first packet: set number of segments
            send_mbufs[pkt_idx][0]->nb_segs = nb_segs_per_packet;

            // for last packet: set next as null
            send_mbufs[pkt_idx][nb_segs_per_packet - 1]->next = NULL;
        } else {
            // single buffer for this packet
            send_mbufs[pkt_idx][0] = (struct mbuf *)mempool_alloc(&mbuf_mempool);
            // allocate backing buffer for this mbuf
            unsigned char *buffer = (unsigned char *)mempool_alloc(&tx_buf_mempool);
            mbuf_init(send_mbufs[pkt_idx][0],
                        buffer,
                        DATA_MBUFS_SIZE,
                        0);
            // set release as non zero-copy release function
            send_mbufs[pkt_idx][0]->release = tx_completion;
            send_mbufs[pkt_idx][0]->next = NULL; // set the next packet as null
            for (int seg = 0; seg < nb_segs_per_packet; seg++) {
                void *server_memory = get_server_region(server_working_set, 
                                                            segments[segment_array_idx],
                                                            segment_size);
                // TODO: handle case where header is NOT initialized in memory
                NETPERF_DEBUG("Copying into offset %u of mbuf", (unsigned)(seg * segment_size));
                mbuf_copy(send_mbufs[pkt_idx][0], 
                            (char *)server_memory,
                            segment_size,
                            seg * segment_size);
                segment_array_idx += 1;

            }

            // for the first packet, set the number of segmens
            send_mbufs[pkt_idx][0]->nb_segs = 1;
        }

        // for each first packet, copy in the ID
        uint64_t *id_pointer = mbuf_offset(send_mbufs[pkt_idx][0], 
                                            FULL_HEADER_SIZE + sizeof(uint64_t),
                                            uint64_t *);
        *id_pointer = id;
        send_mbufs[pkt_idx][0]->pkt_len = pkt_len;
    }

    // now actually transmit the packets
    int total_sent = 0;
    while (total_sent < total_packets_required) {
        int sent = mlx5_transmit_batch(send_mbufs, 
                                        total_sent, // index to start on
                                        total_packets_required - total_sent, // tota
                                        &txqs[0]);
        total_sent += sent;
    }

    return 0;
}

int do_server() {
    NETPERF_DEBUG("Starting server program");
    struct mbuf *recv_mbufs[BURST_SIZE];
    int total_packets_required = calculate_total_packets_required((size_t)segment_size, (size_t)num_segments);
    int num_received = 0;
    while (1) {
        num_received = mlx5_gather_rx((struct mbuf **)&recv_mbufs, 
                                        BURST_SIZE,
                                        &rx_buf_mempool,
                                        &rxqs[0]);
        if (num_received > 0) {
            for (int  i = 0; i < num_received; i++) {
                struct mbuf *pkt = recv_mbufs[i];
                void *payload_out = NULL;
                uint32_t payload_len = 0;
                if (check_valid_packet(pkt, 
                                        &payload_out, 
                                        &payload_len, 
                                        &server_mac) != 1) {
                    NETPERF_DEBUG("Received invalid pkt");
                    mbuf_free(pkt);
                    continue;
                }
                int ret = process_server_request(pkt, 
                                                    payload_out, 
                                                    payload_len,
                                                    total_packets_required);
                RETURN_ON_ERR(ret, "Error processing request");
                mbuf_free(pkt);
            }
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    int ret = 0;
    seed_rand();
    NETPERF_DEBUG("In netperf program");
    ret = parse_args(argc, argv);
    if (ret) {
        NETPERF_WARN("parse_args() failed.");
    }

    // Global time initialization
    ret = time_init();
    if (ret) {
        NETPERF_WARN("Time initialization failed.");
        return ret;
    }

    // Mlx5 queue and flow initialization
    ret = init_mlx5();
    if (ret) {
        NETPERF_WARN("init_mlx5() failed.");
        return ret;
    }

    // initialize the workload
    ret = init_workload();
    if (ret) {
        NETPERF_WARN("Init of workload failed.");
        return ret;
    }

    if (mode == UDP_CLIENT) {
        ret = do_client();
        if (ret) {
            NETPERF_WARN("Client returned non-zero status.");
            return ret;
        }
    } else {
        return do_server();
    }

    return ret;
}


