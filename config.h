// (C) 2021 by folkert@vanheusden.com
// released under Apache license v2.0

#define WITH_BACKTRACE

#define WITH_TIMESTAMP

#define CALLER_DEPTH 8

#define PREVENT_RECURSION  // required at least on RHEL and Fedora

#define CAPTURE_PTHREAD_EXIT

#define STORE_THREAD_NAME

#define WITH_COLORS

#define USE_CLOCK CLOCK_REALTIME
#define MEASURE_TIMING

#define MUTEX_SANITY_CHECKS

#define RWLOCK_SANITY_CHECKS

// slower start-up, potentially less latency while measuring
#define PREALLOCATE
