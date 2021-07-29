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
#include <base/page.h>
#include <base/pci.h>
#include <util/udma_barrier.h>
#include <mlx5.h>
#include <infiniband/verbs.h>
#include <infiniband/mlx5dv.h>
/**********************************************************************/
// CONSTANTS
#define MBUF_DEFAULT_LEN 8192 // might need to change depending on the size of the actual mbuf struct
#define MBUF_DEFAULT_HEADROOM 128
#define NUM_BUFS_PER_PAGE 256
#define TOTAL_MEMPOOL_PAGES 40


/**********************************************************************/

/**********************************************************************/
// STATIC STATE
static struct mempool rx_buf_mempool;
struct mempool tx_buf_mempool;
static struct hardware_q *rxq_out[1];
static struct direct_txq *txq_out[1];
static bool cfg_pci_addr_specified;
static struct ibv_context *context;
static struct ibv_pd *pd;
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


