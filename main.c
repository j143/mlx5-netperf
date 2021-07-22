#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <util/udma_barrier.h>
#include <debug.h>

int main() {
    NETPERF_DEBUG("In netperf program");
    udma_to_device_barrier();
    return 0;
}
