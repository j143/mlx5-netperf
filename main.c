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
static int has_latency_log = 1;
static char *latency_log;
static RateDistribution rate_distribution = {.type = UNIFORM, .rate_pps = 5000, .total_time = 2};
static ClientRequest *client_requests = NULL; // pointer to client request information
static OutgoingHeader header = {}; // header to copy in to the request
static Latency_Dist_t latency_dist = { .min = LONG_MAX, .max = 0, .total_count = 0, .latency_sum = 0 };
static Packet_Map_t packet_map = {.total_count = 0, .grouped_rtts = NULL, .sent_ids = NULL };

static struct mempool rx_buf_mempool;
static struct mempool tx_buf_mempool;
static struct mempool mbuf_mempool;
static void *server_working_set;
static struct mlx5_rxq rxqs[NUM_QUEUES];
static struct mlx5_txq txqs[NUM_QUEUES];
static struct ibv_context *context;
static struct ibv_pd *pd;
static struct ibv_mr *tx_mr;
static struct ibv_mr *rx_mr;
static struct pci_addr nic_pci_addr;
static size_t max_inline_data = 256;
static uint32_t total_dropped;

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
        // timestamp, packet id, 1 uint64_t per segment
        size_t client_payload_size = sizeof(uint64_t) * ( 2 + num_segments );
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
                                        &server_working_set,
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

/*
 * mlx5_gather_completions - collect up to budget received packets and completions
 */
int mlx5_gather_completions(struct mbuf **mbufs, struct mlx5_txq *v, unsigned int budget)
{
	struct mlx5dv_cq *cq = &v->tx_cq_dv;
	struct mlx5_cqe64 *cqe, *cqes = cq->buf;

	unsigned int compl_cnt;
	uint8_t opcode;
	uint16_t wqe_idx;

	for (compl_cnt = 0; compl_cnt < budget; compl_cnt++, v->cq_head++) {
		cqe = &cqes[v->cq_head & (cq->cqe_cnt - 1)];
		opcode = cqe_status(cqe, cq->cqe_cnt, v->cq_head);

		if (opcode == MLX5_CQE_INVALID)
			break;

		PANIC_ON_TRUE(opcode != MLX5_CQE_REQ, "wrong opcode");

		PANIC_ON_TRUE(mlx5_get_cqe_format(cqe) == 0x3, "wrong cqe format");

		wqe_idx = be16toh(cqe->wqe_counter) & (v->tx_qp_dv.sq.wqe_cnt - 1);
		mbufs[compl_cnt] = load_acquire(&v->buffers[wqe_idx]);
	}

	cq->dbrec[0] = htobe32(v->cq_head & 0xffffff);

	return compl_cnt;
}

/*
 * mlx5_transmit_one - send one mbuf
 * @m: mbuf to send
 *
 * returns 0 on success, -1 on error
 */
int mlx5_transmit_one(struct mbuf *m)
{
	int i, compl = 0;
	struct mlx5_txq *v = &txqs[0];
	uint32_t idx = v->sq_head & (v->tx_qp_dv.sq.wqe_cnt - 1);
	struct mbuf *mbs[SQ_CLEAN_MAX];
	struct mlx5_wqe_ctrl_seg *ctrl;
	struct mlx5_wqe_eth_seg *eseg;
	struct mlx5_wqe_data_seg *dpseg;
	void *segment;

	if (nr_inflight_tx(v) >= SQ_CLEAN_THRESH) {
		compl = mlx5_gather_completions(mbs, v, SQ_CLEAN_MAX);
		for (i = 0; i < compl; i++)
            // TODO: how does this know what to even do???
			mbuf_free(mbs[i]);
		if (unlikely(nr_inflight_tx(v) >= v->tx_qp_dv.sq.wqe_cnt)) {
            NETPERF_WARN("txq full");
			return -1;
		}
	}

	segment = v->tx_qp_dv.sq.buf + (idx << v->tx_sq_log_stride);
	ctrl = segment;
	eseg = segment + sizeof(*ctrl);
	dpseg = (void *)eseg + (offsetof(struct mlx5_wqe_eth_seg, inline_hdr) & ~0xf);

	ctrl->opmod_idx_opcode = htobe32(((v->sq_head & 0xffff) << 8) |
					       MLX5_OPCODE_SEND);


    NETPERF_DEBUG("Transmitting mbuf with length %u, data_ptr %p", (unsigned)mbuf_length(m), mbuf_data(m));
	dpseg->byte_count = htobe32(mbuf_length(m));
	dpseg->addr = htobe64((uint64_t)mbuf_data(m));

	/* record buffer */
	store_release(&v->buffers[v->sq_head & (v->tx_qp_dv.sq.wqe_cnt - 1)], m);
	v->sq_head++;

	/* write doorbell record */
	udma_to_device_barrier();
	v->tx_qp_dv.dbrec[MLX5_SND_DBR] = htobe32(v->sq_head & 0xffff);

	/* ring bf doorbell */
	mmio_wc_start();
	mmio_write64_be(v->tx_qp_dv.bf.reg, *(__be64 *)ctrl);
	mmio_flush_writes();

	return 0;

}

void tx_completion(struct mbuf *m) {
    // free the backing store
    mempool_free(&tx_buf_mempool, (void *)m->head);

    // free the actual mbuf struct
    mempool_free(&mbuf_mempool, (void *)m);
}

void rx_completion(struct mbuf *m) {
    // FOR NOW: do not free back to a per thread cache, just free back to the
    // main memmpool
    // TODO: is this the correct thing to free? unclear
    mempool_free(&rx_buf_mempool, (void *)m->head);
}

static inline void mbuf_fill_cqe(struct mbuf *m, struct mlx5_cqe64 *cqe)
{
	uint32_t len;

	len = be32toh(cqe->byte_cnt);

	mbuf_init(m, (unsigned char *)m + RX_BUF_HEAD, len, 0);
	m->len = len;

	m->csum_type = mlx5_csum_ok(cqe);
	m->csum = 0;
	m->rss_hash = mlx5_get_rss_result(cqe);

	m->release = rx_completion;
}

/*
 * mlx5_refill_rxqueue - replenish RX queue with nrdesc bufs
 * @vq: queue to refill
 * @nrdesc: number of buffers to fill
 *
 * WARNING: nrdesc must not exceed the number of free slots in the RXq
 * returns 0 on success, errno on error
 */
static inline int mlx5_refill_rxqueue(struct mlx5_rxq *vq, int nrdesc)
{
	unsigned int i;
	uint32_t index;
	unsigned char *buf;
	struct mlx5_wqe_data_seg *seg;

	struct mlx5dv_rwq *wq = &vq->rx_wq_dv;

    // TODO: what does this assertion acutally do?
    // Is this nrdesc must not exceed the number of free slots in the RXq?
	NETPERF_ASSERT(wraps_lte(nrdesc + vq->wq_head, vq->consumer_idx + wq->wqe_cnt), "Wraparound assertion failed");

	for (i = 0; i < nrdesc; i++) {
        buf = mempool_alloc(&rx_buf_mempool);
		if (unlikely(!buf)) {
            NETPERF_ERROR("No buf left");
			return -ENOMEM;
        }

		index = vq->wq_head++ & (wq->wqe_cnt - 1);
		seg = wq->buf + (index << vq->rx_wq_log_stride);
		seg->addr = htobe64((unsigned long)buf + RX_BUF_HEAD);
		vq->buffers[index] = buf;
	}

	udma_to_device_barrier();
	wq->dbrec[0] = htobe32(vq->wq_head & 0xffff);

	return 0;

}

int mlx5_gather_rx(struct mbuf **ms, unsigned int budget)
{
	uint8_t opcode;
	uint16_t wqe_idx;
	int rx_cnt;

	struct mlx5_rxq *v = &rxqs[0];
	struct mlx5dv_rwq *wq = &v->rx_wq_dv;
	struct mlx5dv_cq *cq = &v->rx_cq_dv;

	struct mlx5_cqe64 *cqe, *cqes = cq->buf;
	struct mbuf *m;

	for (rx_cnt = 0; rx_cnt < budget; rx_cnt++, v->consumer_idx++) {
		cqe = &cqes[v->consumer_idx & (cq->cqe_cnt - 1)];
		opcode = cqe_status(cqe, cq->cqe_cnt, v->consumer_idx);

		if (opcode == MLX5_CQE_INVALID) {
			break;
        }

		if (unlikely(opcode != MLX5_CQE_RESP_SEND)) {
            NETPERF_PANIC("got opcode %02X", opcode);
            exit(1);
		}

        // TODO: some statistics thing we should add in later
		total_dropped += be32toh(cqe->sop_drop_qpn) >> 24;
        NETPERF_INFO("Total dropped: %d", total_dropped);


		PANIC_ON_TRUE(mlx5_get_cqe_format(cqe) == 0x3, "not compressed"); // not compressed
		wqe_idx = be16toh(cqe->wqe_counter) & (wq->wqe_cnt - 1);
		m = v->buffers[wqe_idx];
		mbuf_fill_cqe(m, cqe);
		ms[rx_cnt] = m;
	}

	if (unlikely(!rx_cnt))
		return rx_cnt;

	cq->dbrec[0] = htobe32(v->consumer_idx & 0xffffff);
	PANIC_ON_TRUE(mlx5_refill_rxqueue(v, rx_cnt), "failed to refill rx queue");
    NETPERF_INFO("Rx cnt: %u", (unsigned)rx_cnt);

	return rx_cnt;
}

int check_valid_packet(struct mbuf *mbuf, void **payload_out, uint32_t *payload_len, struct eth_addr *our_eth) {
    NETPERF_DEBUG("Mbuf addr: %p, mbuf data addr: %p, diff: %lu, mbuf len: %u", mbuf, mbuf->data, (char *)(mbuf->data) - (char *)mbuf, (unsigned)(mbuf_length(mbuf)));
    unsigned char *ptr = mbuf->data;
    struct eth_hdr * const eth = (struct eth_hdr *)ptr;
    ptr += sizeof(struct eth_hdr);
    struct ip_hdr * const ipv4 = (struct ip_hdr *)ptr;
    ptr += sizeof(struct ip_hdr);
    struct udp_hdr *const udp = (struct udp_hdr *)ptr;
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

    NETPERF_DEBUG("Valid ethernet header");
    // check IP header
    if (ipv4->proto != IPPROTO_UDP) {
        NETPERF_DEBUG("Bad recv type: %u", (unsigned)ipv4->proto);
    }
    
    NETPERF_DEBUG("Ipv4 checksum: %u, Ipv4 ttl: %u, udp checksum: %u", (unsigned)(ntohs(ipv4->chksum)), (unsigned)ipv4->ttl, (unsigned)(ntohs(udp->chksum)));

    // TODO: finish checks
    *payload_out = (void *)ptr;
    *payload_len = mbuf_length(mbuf) - FULL_HEADER_SIZE;
    return 1;

}

int do_client() {
    NETPERF_DEBUG("Starting client");
    struct mbuf *recv_pkts[BURST_SIZE];
    struct mbuf *pkt;
    size_t client_payload_size = sizeof(uint64_t) * (num_segments + 2);
    int total_packets_per_request = calculate_total_packets_required((uint32_t)segment_size, (uint32_t)num_segments);
    
    size_t num_received = 0;
    size_t outstanding = 0;

    uint64_t total_cycles = seconds_to_cycles(rate_distribution.total_time);
    uint64_t start_cycle_offset = microcycles(); // for calculating received latencies
    uint64_t start_time_offset = cycles_to_us(start_cycle_offset);
    
    // first client request (first packet sent at time 0)
    ClientRequest *current_request = get_client_req(client_requests, 0);

    // main processing loop
    while (microcycles() < (start_cycle_offset + total_cycles)) {
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
        mbuf_copy(pkt, (char *)&header, sizeof(OutgoingHeader), 0);
        mbuf_copy(pkt, (char *)current_request, client_payload_size, sizeof(OutgoingHeader));

        int sent = -1;
        NETPERF_DEBUG("Attempting to transmit packet %u (send time %u), outstanding %u", (unsigned)current_request->packet_id, (unsigned)current_request->timestamp_offset, (unsigned)num_received);
        while (sent != 0) {
            sent = mlx5_transmit_one(pkt);
        }
        
        outstanding += total_packets_per_request;
        num_received += 1;
        current_request += 1;

        while (outstanding > 0) {
            int nb_rx = mlx5_gather_rx((struct mbuf **)&recv_pkts, 32);
            if (nb_rx == 0) {
                // if time to send the next packet, break
                if (microtime() >= (current_request->timestamp_offset + start_time_offset)) {
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
                uint64_t timestamp = *(uint64_t *)payload;
                uint64_t id = *(uint64_t *)((char *)payload + sizeof(uint64_t));
                uint64_t rtt = microcycles() - start_time_offset - timestamp;
                add_latency_to_map(&packet_map, rtt, id);

                // free back the received packet
                mbuf_free(recv_pkts[i]);
            }
        }

        // wait till time to send the next packet
        while (microtime() < (current_request->timestamp_offset + start_time_offset)) {}
    }

    // dump the packets
    uint64_t total_time = microtime() - start_time_offset;
    size_t total_sent = (size_t)current_request->packet_id - 1;
    free(client_requests);
    calculate_and_dump_latencies(&packet_map,
                                    &latency_dist,
                                    total_sent,
                                    total_packets_per_request,
                                    total_time,
                                    num_segments * segment_size,
                                    rate_distribution.rate_pps,
                                    has_latency_log,
                                    latency_log);
    return 0;
}

int do_server() {
    NETPERF_DEBUG("Starting do server");
    // poll for receiving packets
    struct mbuf *recv_mbufs[BURST_SIZE];
    // uint64_t segments[MAX_SCATTERS];

    int num_received = 0;
    while (1) {
        num_received = mlx5_gather_rx((struct mbuf **)&recv_mbufs, BURST_SIZE);
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

                // process the request
                
                
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


