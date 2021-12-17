// (C) 2021 by folkert@vanheusden.com
// released under Apache license v2.0

#define WITH_BACKTRACE
// get this number of function calls from the stack
#define CALLER_DEPTH 8

#define PREVENT_RECURSION  // required at least on RHEL and Fedora

#define CAPTURE_PTHREAD_EXIT

#define STORE_THREAD_NAME

#define WITH_COLORS

// if you don't care about timing measurements, then comment out
// 'MEASURE_TIMING'. this makes measuring a bit faster(!)
#define USE_CLOCK CLOCK_REALTIME
#define MEASURE_TIMING

// these are at run-time and cause a small delay
#define MUTEX_SANITY_CHECKS
#define RWLOCK_SANITY_CHECKS

// slower start-up, potentially less latency while measuring
#define PREALLOCATE
