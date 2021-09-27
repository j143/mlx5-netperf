#pragma once
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>

#include <asm/ops.h>
#include <base/debug.h>
#include <base/time.h>
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
// STATIC STATE VISIBLE ACROSS PROGRAM
extern struct mempool rx_buf_mempool;
extern struct mempool tx_buf_mempool;
extern struct mempool mbuf_mempool;
extern uint32_t total_dropped;

/*
 * mlx5_gather_completions - collect up to budget received packets and completions
 */
int mlx5_gather_completions(struct mbuf **mbufs, 
                            struct mlx5_txq *v, 
                            unsigned int budget);


/* 
 * mlx5_transmit_one - send one mbuf
 * @m: mbuf to send - can potentially be a scattered list of mbufs
 * @v: tx queue
 * returns 1 on sent, 0 on error.
 */
int mlx5_transmit_one(struct mbuf *m, struct mlx5_txq *v);

/*
 * mlx5_transmit_batch - send a batch of mbuf,
 * @mbufs: array of mbufs to send - which could each potentially be scattered
 * @start_index: which index to start sending from (must be <= burst_size)
 * @burst_size: number of mbufs to send
 * @v: tx queue
 *
 * Returns number of successfully transmitted mbufs on success.
 */
int mlx5_transmit_batch(struct mbuf *mbufs[MAX_PACKETS][MAX_SCATTERS],
                        size_t start_index,
                        size_t burst_size,
                        struct mlx5_txq *v);

/* 
 * Gather received packets
 * */
int mlx5_gather_rx(struct mbuf **ms, 
                    unsigned int budget, 
                    struct mempool *rx_buf_mempool,
                    struct mlx5_rxq *v);


// potentially must free any further mbufs as well
static inline void zero_copy_tx_completion(struct mbuf *m)
{
    while (m != NULL) {
        struct mbuf *next_mbuf = m->next;
        mempool_free(&mbuf_mempool, (void *)m);
        m = next_mbuf;
    }
}

static inline void tx_completion(struct mbuf *m) {
    while (m != NULL) {
        struct mbuf *next_mbuf = m->next;
        mempool_free(&tx_buf_mempool, (void *)m->head);

        // free the actual mbuf struct
        mempool_free(&mbuf_mempool, (void *)m);

        m = next_mbuf;
    }
}

static inline void rx_completion(struct mbuf *m) {
    // FOR NOW: do not free back to a per thread cache, just free back to the
    // main memmpool
    // TODO: is this the correct thing to free? unclear
    mempool_free(&rx_buf_mempool, (void *)m->head);
}

static inline void mbuf_fill_cqe(struct mbuf *m, struct mlx5_cqe64 *cqe) {
	uint32_t len;

	len = be32toh(cqe->byte_cnt);

	mbuf_init(m, (unsigned char *)m, len, RX_BUF_HEAD);
	m->len = len - RX_BUF_HEAD;
    NETPERF_ASSERT(((char *)(m->data) - (char *)m) == RX_BUF_HEAD, "rx mbuf data pointer not set correctly");

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
static inline int mlx5_refill_rxqueue(struct mlx5_rxq *vq, 
                                        int nrdesc, 
                                        struct mempool *rx_buf_mempool)
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
        buf = mempool_alloc(rx_buf_mempool);
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









