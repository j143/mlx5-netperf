/*
 * busy_work.c - Utilities for adding busy work.
 */

#include <inttypes.h>
#include <math.h>       /* sqrt */

#include <base/busy_work.h>
#include <base/debug.h>
#include <base/time.h>

double busy_work(size_t i) {
    float k = 2350845.545;
    return sqrt((k*(float)i));
}

uint64_t time_iterations(size_t iterations) {
    uint64_t trials = 100;
    uint64_t start = cycletime(); 

    for (uint64_t i = 0; i < trials; i++) {
        do_busy_work(iterations);
        i += 1;
    }

    uint64_t ret = cycles_to_ns((float)(cycletime() - start) / (float)trials);
    return ret;
}

size_t calibrate_busy_work(uint64_t target_us) {
    uint64_t target_ns = target_us * 1000;
    size_t iterations = 0;
    if (target_us > 0) {
        iterations += 1;
        while ((time_iterations(iterations) < target_ns)) {
            iterations *= 2;
        }

        while (time_iterations(iterations) > target_ns) {
            iterations -= 1;
        }
    }

    NETPERF_WARN("For busy work of %lu us, run %lu iterations; takes %lu ns", target_us, iterations, time_iterations(iterations));
    return iterations;
}

void do_busy_work(size_t iters) {
    for (size_t i = 0; i < iters; i++) {
        busy_work(i);
    }
}

