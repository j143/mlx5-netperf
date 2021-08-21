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

#include <base/debug.h>
#include <base/parse.h>
#include <base/mem.h>
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

static unsigned char rss_key[40] = {
	0x82, 0x19, 0xFA, 0x80, 0xA4, 0x31, 0x06, 0x59, 0x3E, 0x3F, 0x9A,
	0xAC, 0x3D, 0xAE, 0xD6, 0xD9, 0xF5, 0xFC, 0x0C, 0x63, 0x94, 0xBF,
	0x8F, 0xDE, 0xD2, 0xC5, 0xE2, 0x04, 0xB1, 0xCF, 0xB1, 0xB1, 0xA1,
	0x0D, 0x6D, 0x86, 0xBA, 0x61, 0x78, 0xEB};

static struct ibv_flow *eth_flow;
static struct mempool rx_buf_mempool;
static struct mempool tx_buf_mempool;
static struct mempool mbuf_mempool;
static void *server_working_set;
static struct mlx5_rxq rxqs[NUM_QUEUES];
static struct direct_txq *txq_out[NUM_QUEUES];
static struct mlx5_txq txqs[NUM_QUEUES];
static struct ibv_context *context;
static struct ibv_pd *pd;
static struct ibv_mr *tx_mr;
static struct ibv_mr *rx_mr;
static struct pci_addr nic_pci_addr;
static uint32_t total_dropped;

/**********************************************************************/
/*
 * simple_alloc - simple memory allocator for internal MLX5 structures
 */
/*static void *simple_alloc(size_t size, void *priv_data)
{
    return malloc(size);
}

static void simple_free(void *ptr, void *priv_data) {
    free(ptr);
}*/

// TODO: this was to put the rx ring in shared memory to enable work stealing.
/*static struct mlx5dv_ctx_allocators dv_allocators = {
	.alloc = simple_alloc,
	.free = simple_free,
};*/

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
        {"segment_size", optional_argument, 0, 'l'},
        {"array_size", optional_argument, 0, 'a'},
        {"zero_copy", no_argument, 0, 'z'},
        {0,           0,                 0,  0   }
    };
    int long_index = 0;
    int ret;
    while ((opt = getopt_long(argc, argv, "m:w:c:e:i:s:k:l:a:z:",
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
                NETPERF_INFO("Parsed our eth addr: %s", optarg);
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
            case 'l': // segment_size
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
            default:
                NETPERF_WARN("Invalid arguments");
                exit(EXIT_FAILURE);
        }
    }
    return 0;
}


int mlx5_init_flows(int num_rx_queues) {
    return 0;
}

int mlx5_qs_init_flows(struct mlx5_rxq *v)
{
	struct ibv_wq *ind_tbl[1] = {v->rx_wq};
	struct ibv_rwq_ind_table_init_attr rwq_attr = {0};
	rwq_attr.ind_tbl = ind_tbl;
    rwq_attr.log_ind_tbl_size = __builtin_ctz(1);
    rwq_attr.comp_mask = 0;
	v->rwq_ind_table = ibv_create_rwq_ind_table(context, &rwq_attr);
	if (!v->rwq_ind_table) {
        NETPERF_WARN("Failed to create rx indirection table");
		return -errno;
    }

	struct ibv_rx_hash_conf rss_cnf = {
		.rx_hash_function = IBV_RX_HASH_FUNC_TOEPLITZ,
		.rx_hash_key_len = ARRAY_SIZE(rss_key),
		.rx_hash_key = rss_key,
		.rx_hash_fields_mask = IBV_RX_HASH_SRC_IPV4 | IBV_RX_HASH_DST_IPV4 | IBV_RX_HASH_SRC_PORT_UDP | IBV_RX_HASH_DST_PORT_UDP,
	};

	struct ibv_qp_init_attr_ex qp_ex_attr = {
		.qp_type = IBV_QPT_RAW_PACKET,
		.comp_mask = IBV_QP_INIT_ATTR_RX_HASH | IBV_QP_INIT_ATTR_IND_TABLE | IBV_QP_INIT_ATTR_PD,
		.pd = pd,
		.rwq_ind_tbl = v->rwq_ind_table,
		.rx_hash_conf = rss_cnf,
	};

	v->qp = ibv_create_qp_ex(context, &qp_ex_attr);
	if (!v->qp) {
        NETPERF_WARN("Failed to create rx qp");
		return -errno;
    }

    struct eth_addr *our_eth = &client_mac;
    if (mode == UDP_SERVER) {
        NETPERF_DEBUG("Setting eth as server_mac");
        our_eth = &server_mac;
    }

    /* *Register sterring rules to intercept packets to our mac address and
     * place packet in ring pointed by v->qp */
    struct raw_eth_flow_attr {
        struct ibv_flow_attr attr;
        struct ibv_flow_spec_eth spec_eth;
    } __attribute__((packed)) flow_attr = {
        .attr = {
            .comp_mask = 0,
            .type = IBV_FLOW_ATTR_NORMAL,
            .size = sizeof(flow_attr),
            .priority = 0,
            .num_of_specs = 1,
            .port = PORT_NUM, // what port is this? dpdk port?
            .flags = 0,
        },
        .spec_eth = {
            .type = IBV_FLOW_SPEC_ETH,
            .size = sizeof(struct ibv_flow_spec_eth),
            .val = {
                .src_mac = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                .ether_type = 0,
                .vlan_tag = 0,
            },
            .mask = {
                .dst_mac = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
                .src_mac = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                .ether_type = 0,
                .vlan_tag = 0,
            }
        }
    };
    rte_memcpy(&flow_attr.spec_eth.val.dst_mac, our_eth, 6);
    
    // Do some minimal RSS stuff so we receive packets
    eth_flow = ibv_create_flow(v->qp, &flow_attr.attr);
    if (!eth_flow) {
        NETPERF_ERROR("Not able to create eth_flow: %s", strerror(errno));
        return -errno;
    }

    return 0;
}

// TODO:
//  on the tx side: we will need to actually rewrite the logic here
//  to dynamically create the work requests based on the number of
//  scatter-gather elements
//  what happens if you reach the end of the wqe?? how does the wrap around
//  happen
static void mlx5_init_tx_segment(struct mlx5_txq *v, unsigned int idx)
{
	int size;
	struct mlx5_wqe_ctrl_seg *ctrl;
	struct mlx5_wqe_eth_seg *eseg;
	struct mlx5_wqe_data_seg *dpseg;
	void *segment;

	segment = v->tx_qp_dv.sq.buf + idx * v->tx_qp_dv.sq.stride;
	ctrl = segment;
	eseg = segment + sizeof(*ctrl);
	dpseg = (void *)eseg + (offsetof(struct mlx5_wqe_eth_seg, inline_hdr) & ~0xf);

	size = (sizeof(*ctrl) / 16) +
	       (offsetof(struct mlx5_wqe_eth_seg, inline_hdr)) / 16 +
	       sizeof(struct mlx5_wqe_data_seg) / 16;

	/* set ctrl segment */
	*(uint32_t *)(segment + 8) = 0;
	ctrl->imm = 0;
	ctrl->fm_ce_se = MLX5_WQE_CTRL_CQ_UPDATE;
	ctrl->qpn_ds = htobe32(size | (v->tx_qp->qp_num << 8));

	/* set eseg */
	memset(eseg, 0, sizeof(struct mlx5_wqe_eth_seg));
	eseg->cs_flags |= MLX5_ETH_WQE_L3_CSUM | MLX5_ETH_WQE_L4_CSUM;

	/* set dpseg */
	dpseg->lkey = htobe32(tx_mr->lkey);
}

int mlx5_init_txq(int index, struct mlx5_txq *v) {
	int i, ret;

	/* Create a CQ */
	struct ibv_cq_init_attr_ex cq_attr = {
		.cqe = SQ_NUM_DESC,
		.channel = NULL,
		.comp_vector = 0,
		.wc_flags = 0,
		.comp_mask = IBV_CQ_INIT_ATTR_MASK_FLAGS,
		.flags = IBV_CREATE_CQ_ATTR_SINGLE_THREADED,
	};
	struct mlx5dv_cq_init_attr dv_cq_attr = {
		.comp_mask = 0,
	};
	v->tx_cq = mlx5dv_create_cq(context, &cq_attr, &dv_cq_attr);
	if (!v->tx_cq) {
        NETPERF_WARN("Could not create tx cq: %s", strerror(errno));
		return -errno;
    }

	/* Create a 1-sided queue pair for sending packets */
    // TODO: understand the relationship between max_send_sge and how much it's
    // possible to actually scatter-gather
	struct ibv_qp_init_attr_ex qp_init_attr = {
		.send_cq = ibv_cq_ex_to_cq(v->tx_cq),
		.recv_cq = ibv_cq_ex_to_cq(v->tx_cq),
		.cap = {
			.max_send_wr = SQ_NUM_DESC,
			.max_recv_wr = 0,
			.max_send_sge = 1, // TODO: does TX scatter-gather still work if this is 1?
			.max_inline_data = 256,
		},
		.qp_type = IBV_QPT_RAW_PACKET,
		.sq_sig_all = 1,
		.pd = pd,
		.comp_mask = IBV_QP_INIT_ATTR_PD
	};
	struct mlx5dv_qp_init_attr dv_qp_attr = {
		.comp_mask = 0,
	};
	v->tx_qp = mlx5dv_create_qp(context, &qp_init_attr, &dv_qp_attr);
	if (!v->tx_qp) {
        NETPERF_WARN("Could not create tx qp: %s", strerror(errno));
		return -errno;
    }

	/* Turn on TX QP in 3 steps */
    // TODO: why are these three steps required
	struct ibv_qp_attr qp_attr;
	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IBV_QPS_INIT;
	qp_attr.port_num = 1;
	ret = ibv_modify_qp(v->tx_qp, &qp_attr, IBV_QP_STATE | IBV_QP_PORT);
	if (ret) {
        NETPERF_WARN("Could not modify tx qp for IBV_QPS_INIT (1st step)");
		return -ret;
    }

	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IBV_QPS_RTR;
	ret = ibv_modify_qp(v->tx_qp, &qp_attr, IBV_QP_STATE);
	if (ret) {
        NETPERF_WARN("Could not modify tx_qp for IBV_QPS_RTR (2nd step)");
		return -ret;
    }

	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IBV_QPS_RTS;
	ret = ibv_modify_qp(v->tx_qp, &qp_attr, IBV_QP_STATE);
	if (ret) {
        NETPERF_WARN("Could not modify tx_qp for IBV_QPS_RTS (3rd step)");
		return -ret;
    }

	struct mlx5dv_obj obj = {
		.cq = {
			.in = ibv_cq_ex_to_cq(v->tx_cq),
			.out = &v->tx_cq_dv,
		},
		.qp = {
			.in = v->tx_qp,
			.out = &v->tx_qp_dv,
		},
	};
	ret = mlx5dv_init_obj(&obj, MLX5DV_OBJ_CQ | MLX5DV_OBJ_QP);
	if (ret) {
        NETPERF_WARN("Could not init mlx5dv_obj");
		return -ret;
    }

	PANIC_ON_TRUE(!is_power_of_two(v->tx_cq_dv.cqe_size), "tx cqe_size not power of two");
	PANIC_ON_TRUE(!is_power_of_two(v->tx_qp_dv.sq.stride), "tx stride size not power of two");
	v->tx_sq_log_stride = __builtin_ctz(v->tx_qp_dv.sq.stride);
	v->tx_cq_log_stride = __builtin_ctz(v->tx_cq_dv.cqe_size);

	/* allocate list of posted buffers */
	v->buffers = aligned_alloc(CACHE_LINE_SIZE, v->tx_qp_dv.sq.wqe_cnt * sizeof(*v->buffers));
	if (!v->buffers) {
        NETPERF_WARN("Could not alloc tx wqe buffers");
		return -ENOMEM;
    }

    // init each tx wqe
	for (i = 0; i < v->tx_qp_dv.sq.wqe_cnt; i++)
		mlx5_init_tx_segment(v, i);

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

    // init single rxq and single txq
    // Here is where, if we ever want more than one rxq/txq, we'd init more
    // the array
    ret = mlx5_init_rxq(&rxqs[0], &rx_buf_mempool, context, pd, rx_mr);
    RETURN_ON_ERR(ret, "Failed to create rxq: %s", strerror(-ret));

    ret = mlx5_qs_init_flows(&rxqs[0]);
    if (ret) {
        NETPERF_ERROR("Failed to init flows for listening");
    }

    // do we need to install ANY rules for plain packets to show up?
    /*ret = mlx5_init_flows(NUM_QUEUES);
    if (ret) {
        NETPERF_ERROR("Failed to init flows");
        return ret;
    }*/

    ret = mlx5_init_txq(0, &txqs[0]);
    if (ret) {
        NETPERF_ERROR("Failed to create txq");
        return ret;
    }
    txq_out[0] = &txqs[0].txq;

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
 * uses local kthread tx queue
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
    unsigned char *ptr = mbuf->data;
    struct eth_hdr * const eth = (struct eth_hdr *)ptr;
    ptr += sizeof(struct eth_hdr *);
    struct ip_hdr * const ipv4 = (struct ip_hdr *)ptr;
    ptr += sizeof(struct ip_hdr *);
    struct udp_hdr *const udp = (struct udp_hdr *)ptr;
    ptr += sizeof(struct udp_hdr*);

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
    
    NETPERF_DEBUG("Ipv4 checksum: %u, udp checksum: %u", (unsigned)(ntohs(ipv4->chksum)), (unsigned)(ntohs(udp->chksum)));

    // TODO: finish checks
    *payload_out = (void *)ptr;
    *payload_len = mbuf_length(mbuf) - FULL_HEADER_SIZE;
    return 1;

}

int do_client() {
    // TX window???
    struct mbuf MBUFS[32];
    uint16_t message_size = 100;


    // for now: send a SINGLE packet to the other side and make sure it's
    // received
    unsigned char *data = (unsigned char *)mempool_alloc(&tx_buf_mempool);
    struct mbuf *mbuf = &MBUFS[0];
    mbuf_init(mbuf, data, 1024, 0);
    
    // fill in the mbuf
    struct eth_hdr *eth = mbuf_put_hdr(mbuf, struct eth_hdr);
    struct ip_hdr *ipv4 = mbuf_put_hdr(mbuf, struct ip_hdr);
    struct udp_hdr *udp = mbuf_put_hdr(mbuf, struct udp_hdr);
    unsigned char *data_ptr = mbuf_put(mbuf, message_size);

    // fill in the ethernet header
    ether_addr_copy(&client_mac, &eth->shost);
    ether_addr_copy(&server_mac, &eth->dhost);

    // TODO: turn these into debug asserts
    NETPERF_ASSERT(eth_addr_equal(&eth->shost, &client_mac) == 1, "Source addrs not equal");
    NETPERF_ASSERT(eth_addr_equal(&eth->dhost, &server_mac) == 1, "Dest addrs not equal");
    eth->type = htons(ETHTYPE_IP);
    
    // fill in the ipv4 header
    ipv4->tos = 0x0;
    ipv4->len = htons(sizeof(struct ip_hdr) + sizeof(struct udp_hdr) + message_size);
    ipv4->id = htons(1);
    ipv4->off = 0;
    ipv4->ttl = 64;
    ipv4->proto = IPPROTO_UDP;
    ipv4->chksum = 0;
    ipv4->saddr = htonl(client_ip);
    ipv4->daddr = htonl(server_ip);

    // fill in the udp header
    udp->src_port = htons(client_port);
    udp->dst_port = htons(server_port);
    udp->len = htons(sizeof(struct udp_hdr));
    udp->chksum = 0;

    // write some data
    memset(data_ptr, 'a', message_size);

    NETPERF_INFO("About to transmit one; ipv4 checksum: %u, udp checksum: %u", (unsigned)(ntohs(ipv4->chksum)), (unsigned)(ntohs(udp->chksum)));
    mlx5_transmit_one(mbuf);
    return 0;
}

int do_server() {
    NETPERF_DEBUG("Starting do server");
    // poll for receiving packets
    struct mbuf *RECV_MBUFS[32];
    int num_received = 0;
    while (1) {
        num_received = mlx5_gather_rx((struct mbuf **)&RECV_MBUFS, 32);
        if (num_received > 0) {
            // received a packet
            // TODO: check that the data in the mbuf is valid
            NETPERF_DEBUG("Received packets: %d", num_received);
            for (int  i = 0; i < num_received; i++) {
                struct mbuf *pkt = RECV_MBUFS[i];
                void *payload_out = NULL;
                uint32_t payload_len = 0;
                if (check_valid_packet(pkt, &payload_out, &payload_len, &server_mac) == 1) {
                    NETPERF_DEBUG("Received valid pkt with length: %u", (unsigned)payload_len);
                }
                mbuf_free(pkt);
            }
        }
    }

    return 0;
}

int main(int argc, char *argv[]) {
    int ret = 0;
    NETPERF_DEBUG("In netperf program");
    ret = parse_args(argc, argv);
    if (ret) {
        NETPERF_WARN("parse_args() failed.");
    }
    ret = init_mlx5();
    if (ret) {
        NETPERF_WARN("init_mlx5() failed.");
        return ret;
    }

    if (mode == UDP_CLIENT) {
        return do_client();
    } else {
        return do_server();
    }
    return ret;
}


