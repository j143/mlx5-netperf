/*
 * busy_work.h - For adding cpu cycles
 */

#include <stddef.h>

double busy_work(size_t i);

double do_busy_work(size_t iters);

size_t calibrate_busy_work(uint64_t target_us);

uint64_t time_iterations(size_t iterations);
