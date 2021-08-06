#pragma once

#include <infiniband/mlx5dv.h>
#include <infiniband/verbs.h>
#include <base/byteorder.h>


/*
 * Direct hardware queue support
 */

struct hardware_q {
	void		*descriptor_table;
	uint32_t	*consumer_idx;
	uint32_t	*shadow_tail;
	uint32_t	descriptor_log_size;
	uint32_t	nr_descriptors;
	uint32_t	parity_byte_offset;
	uint32_t	parity_bit_mask;
};

struct direct_txq {};

struct mlx5_rxq {
    /* handle for runtime */
	struct hardware_q rxq;

	uint32_t consumer_idx;

	struct mlx5dv_cq rx_cq_dv;
	struct mlx5dv_rwq rx_wq_dv;
	uint32_t wq_head;
	uint32_t rx_cq_log_stride;
	uint32_t rx_wq_log_stride;

	void **buffers; // array of posted buffers


	struct ibv_cq_ex *rx_cq;
	struct ibv_wq *rx_wq;
	struct ibv_rwq_ind_table *rwq_ind_table;
	struct ibv_qp *qp;
} __aligned(CACHE_LINE_SIZE);

struct mlx5_txq {
    /* handle for runtime */
	struct direct_txq txq;

	/* direct verbs qp */
	struct mbuf **buffers; // pending DMA
	struct mlx5dv_qp tx_qp_dv;
	uint32_t sq_head;
	uint32_t tx_sq_log_stride;

	/* direct verbs cq */
	struct mlx5dv_cq tx_cq_dv;
	uint32_t cq_head;
	uint32_t tx_cq_log_stride;

	struct ibv_cq_ex *tx_cq;
	struct ibv_qp *tx_qp;
};
