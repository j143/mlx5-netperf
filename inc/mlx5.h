#pragma once


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
