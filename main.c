#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <base/debug.h>
#include <base/mem.h>
#include <base/mempool.h>
#include <base/mbuf.h>
#include <base/page.h>
#include <base/pci.h>
#include <util/udma_barrier.h>
#include <util/mmio.h>
#include <mlx5.h>
#include <mlx5_ifc.h>
#include <infiniband/verbs.h>
#include <infiniband/mlx5dv.h>
/**********************************************************************/
// CONSTANTS
#define NUM_BUFS_PER_PAGE 256
#define TOTAL_MEMPOOL_PAGES 40
#define NUM_QUEUES 1
#define RQ_NUM_DESC			1024
#define SQ_NUM_DESC			128
/* space for the mbuf struct */
#define RX_BUF_HEAD \
 (align_up(sizeof(struct mbuf), 2 * CACHE_LINE_SIZE))
/* some NICs expect enough padding for CRC etc.*/
#define RX_BUF_TAIL			64
#define NET_MTU 9216 // jumbo frames is turned on in this interface
/**********************************************************************/

/**********************************************************************/
// STATIC STATE
static struct mempool rx_buf_mempool;
struct mempool tx_buf_mempool;
static struct hardware_q *rxq_out[NUM_QUEUES];
static struct mlx5_rxq rxqs[NUM_QUEUES];
static struct direct_txq *txq_out[NUM_QUEUES];
static struct mlx5_txq txqs[NUM_QUEUES];
static bool cfg_pci_addr_specified;
static struct ibv_context *context;
static struct ibv_pd *pd;
static struct ibv_mr *mr_tx;
static struct ibv_mr *mr_rx;
static struct pci_addr nic_pci_addr;


/**********************************************************************/
/*
 * simple_alloc - simple memory allocator for internal MLX5 structures
 */
static void *simple_alloc(size_t size, void *priv_data)
{
    return malloc(size);
}

static void simple_free(void *ptr, void *priv_data) {
    free(ptr);
}

static struct mlx5dv_ctx_allocators dv_allocators = {
	.alloc = simple_alloc,
	.free = simple_free,
};

static int parse_directpath_pci(const char *val)
{
	int ret;

	ret = pci_str_to_addr(val, &nic_pci_addr);
	if (ret)
		return ret;

	NETPERF_INFO("directpath: specified pci address %s", val);
	cfg_pci_addr_specified = true;
	return 0;
}

static int parse_args(int argc, char *argv[]) {
    // for now, hardcode the pci address
    const char pci_addr[] = "0000:37:00.0";
    parse_directpath_pci(pci_addr);
    return 0;
}

int rx_memory_init() {
    int ret;
    void *rx_buf;
    size_t region_len = NUM_BUFS_PER_PAGE * TOTAL_MEMPOOL_PAGES * MBUF_DEFAULT_LEN;
    rx_buf = mem_map_anom(NULL, region_len, PGSIZE_2MB, 0);
    if (rx_buf == NULL) { 
        NETPERF_DEBUG("mem_map_anom failed: resulting buffer is null.");
        return 1;
    }
    ret = mempool_create(&rx_buf_mempool,
                         rx_buf,
                         region_len,
                         PGSIZE_2MB,
                         MBUF_DEFAULT_LEN);
    if (ret) {
        NETPERF_DEBUG("mempool create failed: %d", ret);
        return ret;
    }
    
    return ret;
}

int tx_memory_init() {
    int ret;
    void *tx_buf;
    size_t region_len = NUM_BUFS_PER_PAGE * TOTAL_MEMPOOL_PAGES * MBUF_DEFAULT_LEN;
    tx_buf = mem_map_anom(NULL, region_len, PGSIZE_2MB, 0);
    if (tx_buf == NULL) { 
        NETPERF_DEBUG("mem_map_anom failed: resulting buffer is null.");
        return 1;
    }
    ret = mempool_create(&tx_buf_mempool,
                         tx_buf,
                         region_len,
                         PGSIZE_2MB,
                         MBUF_DEFAULT_LEN);
    if (ret) {
        NETPERF_DEBUG("mempool create failed: %d", ret);
        return ret;
    }
    return 0;
}

/* borrowed from DPDK */
int
ibv_device_to_pci_addr(const struct ibv_device *device,
			    struct pci_addr *pci_addr)
{
	FILE *file;
	char line[32];
	char path[strlen(device->ibdev_path) + strlen("/device/uevent") + 1];
	snprintf(path, sizeof(path), "%s/device/uevent", device->ibdev_path);

	file = fopen(path, "rb");
	if (!file)
		return -errno;

	while (fgets(line, sizeof(line), file) == line) {
		size_t len = strlen(line);
		int ret;

		/* Truncate long lines. */
		if (len == (sizeof(line) - 1))
			while (line[(len - 1)] != '\n') {
				ret = fgetc(file);
				if (ret == EOF)
					break;
				line[(len - 1)] = ret;
			}
		/* Extract information. */
		if (sscanf(line,
			   "PCI_SLOT_NAME="
			   "%04hx:%02hhx:%02hhx.%hhd\n",
			   &pci_addr->domain,
			   &pci_addr->bus,
			   &pci_addr->slot,
			   &pci_addr->func) == 4) {
			break;
		}
	}
	fclose(file);
	return 0;
}

int mlx5_init_flows(int num_rx_queues) {
    return 0;
}

int mlx5_init_rxq(int index, struct mlx5_rxq *v) {
    int i, ret;
    unsigned char *buf;

	/* Create a CQ */
	struct ibv_cq_init_attr_ex cq_attr = {
		.cqe = RQ_NUM_DESC,
		.channel = NULL,
		.comp_vector = 0,
		.wc_flags = IBV_WC_EX_WITH_BYTE_LEN,
		.comp_mask = IBV_CQ_INIT_ATTR_MASK_FLAGS,
		.flags = IBV_CREATE_CQ_ATTR_SINGLE_THREADED,
	};
	struct mlx5dv_cq_init_attr dv_cq_attr = {
		.comp_mask = 0,
	};
	v->rx_cq = mlx5dv_create_cq(context, &cq_attr, &dv_cq_attr);
	if (!v->rx_cq) {
        NETPERF_WARN("Failed to create rx cq");
        return -errno;
    }

	/* Create the work queue for RX */
	struct ibv_wq_init_attr wq_init_attr = {
		.wq_type = IBV_WQT_RQ,
		.max_wr = RQ_NUM_DESC,
		.max_sge = 1,
		.pd = pd,
		.cq = ibv_cq_ex_to_cq(v->rx_cq),
		.comp_mask = 0,
		.create_flags = 0,
	};
	struct mlx5dv_wq_init_attr dv_wq_attr = {
		.comp_mask = 0,
	};
	v->rx_wq = mlx5dv_create_wq(context, &wq_init_attr, &dv_wq_attr);
	if (!v->rx_wq) {
        NETPERF_ERROR("Failed to create rx work queue");
        return -errno;
    }
    	
    if (wq_init_attr.max_wr != RQ_NUM_DESC)
		NETPERF_WARN("Ring size is larger than anticipated");

	/* Set the WQ state to ready */
	struct ibv_wq_attr wq_attr = {0};
	wq_attr.attr_mask = IBV_WQ_ATTR_STATE;
	wq_attr.wq_state = IBV_WQS_RDY;
	ret = ibv_modify_wq(v->rx_wq, &wq_attr);
	if (ret) {
        NETPERF_WARN("Could not modify wq with wq_attr while setting up rx queue")
		return -ret;
    }

	struct ibv_wq *ind_tbl[1] = {v->rx_wq};
	struct ibv_rwq_ind_table_init_attr rwq_attr = {0};
	rwq_attr.ind_tbl = ind_tbl;
	v->rwq_ind_table = ibv_create_rwq_ind_table(context, &rwq_attr);
	if (!v->rwq_ind_table) {
        NETPERF_WARN("Failed to create rx indirection table");
		return -errno;
    }

	static unsigned char rss_key[40];
	struct ibv_rx_hash_conf rss_cnf = {
		.rx_hash_function = IBV_RX_HASH_FUNC_TOEPLITZ,
		.rx_hash_key_len = ARRAY_SIZE(rss_key),
		.rx_hash_key = rss_key,
		.rx_hash_fields_mask = IBV_RX_HASH_SRC_IPV4 | IBV_RX_HASH_DST_IPV4 | IBV_RX_HASH_SRC_PORT_TCP | IBV_RX_HASH_DST_PORT_TCP,
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

	/* expose direct verbs objects */
	struct mlx5dv_obj obj = {
		.cq = {
			.in = ibv_cq_ex_to_cq(v->rx_cq),
			.out = &v->rx_cq_dv,
		},
		.rwq = {
			.in = v->rx_wq,
			.out = &v->rx_wq_dv,
		},
	};
	ret = mlx5dv_init_obj(&obj, MLX5DV_OBJ_CQ | MLX5DV_OBJ_RWQ);
	if (ret) {
        NETPERF_WARN("Failed to init rx mlx5dv_obj");
		return -ret;
    }

	NETPERF_ASSERT(!is_power_of_two(v->rx_wq_dv.stride), "stride not power of two");
	NETPERF_ASSERT(!is_power_of_two(v->rx_cq_dv.cqe_size), "cqe size not power of two");
	v->rx_wq_log_stride = __builtin_ctz(v->rx_wq_dv.stride);
	v->rx_cq_log_stride = __builtin_ctz(v->rx_cq_dv.cqe_size);

	/* allocate list of posted buffers */
	v->buffers = aligned_alloc(CACHE_LINE_SIZE, v->rx_wq_dv.wqe_cnt * sizeof(void *));
	if (!v->buffers) {
        NETPERF_WARN("Failed to alloc rx posted buffers");
		return -ENOMEM;
    }

	v->rxq.consumer_idx = &v->consumer_idx;
	v->rxq.descriptor_table = v->rx_cq_dv.buf;
	v->rxq.nr_descriptors = v->rx_cq_dv.cqe_cnt;
	v->rxq.descriptor_log_size = __builtin_ctz(sizeof(struct mlx5_cqe64));
	v->rxq.parity_byte_offset = offsetof(struct mlx5_cqe64, op_own);
	v->rxq.parity_bit_mask = MLX5_CQE_OWNER_MASK;

	/* set byte_count and lkey for all descriptors once */
	struct mlx5dv_rwq *wq = &v->rx_wq_dv;
	for (i = 0; i < wq->wqe_cnt; i++) {
		struct mlx5_wqe_data_seg *seg = wq->buf + i * wq->stride;
		seg->byte_count =  htobe32(NET_MTU + RX_BUF_TAIL);
		seg->lkey = htobe32(mr_rx->lkey);

		/* fill queue with buffers */
		buf = mempool_alloc(&rx_buf_mempool);
		if (!buf)
			return -ENOMEM;

		seg->addr = htobe64((unsigned long)buf + RX_BUF_HEAD);
		v->buffers[i] = buf;
		v->wq_head++;
	}

	/* set ownership of cqes to "hardware" */
	struct mlx5dv_cq *cq = &v->rx_cq_dv;
	for (i = 0; i < cq->cqe_cnt; i++) {
		struct mlx5_cqe64 *cqe = cq->buf + i * cq->cqe_size;
		mlx5dv_set_cqe_owner(cqe, 1);
	}

	udma_to_device_barrier();
	wq->dbrec[0] = htobe32(v->wq_head & 0xffff);

    return 0;
}

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
	dpseg->lkey = htobe32(mr_tx->lkey);
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
        NETPERF_WARN("Could not create tx cqe");
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
        NETPERF_WARN("Could not create tx qp");
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

	NETPERF_ASSERT(!is_power_of_two(v->tx_cq_dv.cqe_size), "tx cqe_size not power of two");
	NETPERF_ASSERT(!is_power_of_two(v->tx_qp_dv.sq.stride), "tx stride size not power of two");
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
    int i = 0;

    struct ibv_device **dev_list;
	struct mlx5dv_context_attr attr = {0};
	struct pci_addr pci_addr;

    // initialize rx and tx memory
    ret = rx_memory_init();
    if (ret) {
        return ret;
    }

    ret = tx_memory_init();
    if (ret) {
        return ret;
    }

	dev_list = ibv_get_device_list(NULL);
	if (!dev_list) {
		perror("Failed to get IB devices list");
		return -1;
	}

	for (i = 0; dev_list[i]; i++) {
		if (strncmp(ibv_get_device_name(dev_list[i]), "mlx5", 4))
			continue;

		if (!cfg_pci_addr_specified)
			break;

		if (ibv_device_to_pci_addr(dev_list[i], &pci_addr)) {
			NETPERF_WARN("failed to read pci addr for %s, skipping",
				     ibv_get_device_name(dev_list[i]));
			continue;
		}

		if (memcmp(&pci_addr, &nic_pci_addr, sizeof(pci_addr)) == 0)
			break;
	}

	if (!dev_list[i]) {
		NETPERF_ERROR("mlx5_init: IB device not found");
		return -1;
	}

	attr.flags = MLX5DV_CONTEXT_FLAGS_DEVX;
	context = mlx5dv_open_device(dev_list[i], &attr);
	if (!context) {
	    NETPERF_ERROR("mlx5_init: Couldn't get context for %s (errno %d)",
			ibv_get_device_name(dev_list[i]), errno);
		return -1;
	}

	ibv_free_device_list(dev_list);

	ret = mlx5dv_set_context_attr(context,
		  MLX5DV_CTX_ATTR_BUF_ALLOCATORS, &dv_allocators);
	if (ret) {
		NETPERF_ERROR("mlx5_init: error setting memory allocator");
		return -1;
	}

	pd = ibv_alloc_pd(context);
	if (!pd) {
		NETPERF_ERROR("mlx5_init: Couldn't allocate PD");
		return -1;
	}

    /* Register memory for TX buffers */
    mr_tx = ibv_reg_mr(pd, tx_buf_mempool.buf, tx_buf_mempool.len, IBV_ACCESS_LOCAL_WRITE);
    if (!mr_tx) {
        NETPERF_ERROR("mlx5_init: Failed to register tx mr");
        return -1;
    }
    
    /* Register memory for RX buffers */
    mr_rx = ibv_reg_mr(pd, rx_buf_mempool.buf, rx_buf_mempool.len, IBV_ACCESS_LOCAL_WRITE);
    if (!mr_rx) {
        NETPERF_ERROR("mlx5_init: Failed to register rx mr");
        return -1;
    }

    // init single rxq and single txq
    // Here is where, if we ever want more than one rxq/txq, we'd init more n
    // the array
    ret = mlx5_init_rxq(0, &rxqs[0]);
    if (ret) {
        NETPERF_ERROR("Failed to create rxq");
        return ret;
    }
    rxq_out[0] = &rxqs[0].rxq;

    ret = mlx5_init_flows(NUM_QUEUES);
    if (ret) {
        NETPERF_ERROR("Failed to init flows");
    }

    ret = mlx5_init_txq(0, &txqs[0]);
    if (ret) {
        NETPERF_ERROR("Failed to create txq");
        return ret;
    }
    txq_out[0] = &txqs[0].txq;

    return ret;
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
    return ret;
}


