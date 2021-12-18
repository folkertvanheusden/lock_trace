// (C) 2021 by folkert@vanheusden.com
// released under Apache license v2.0

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <atomic>
#include <dlfcn.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <jansson.h>
#include <limits.h>
#include <map>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/types.h>


#if JSON_INTEGER_IS_LONG_LONG
#else
	#error jansson should have been compiled with JSON_INTEGER_IS_LONG_LONG
#endif

#include "config.h"
#include "lock_tracer.h"

#ifndef __linux__
#warning This program may only work correctly on Linux.
#endif

#define likely(x)       __builtin_expect((x), 1)
#define unlikely(x)     __builtin_expect((x), 0)

uint64_t n_records = 16777216, emit_count_threshold = n_records / 10;
size_t length = 0;
int mmap_fd = -1;
char *data_filename = nullptr;

bool verbose = false;

bool fork_warning = false;
bool exited = false;
bool enforce_error_check = false;

static void color(const char *str)
{
#ifdef WITH_COLORS
	if (isatty(fileno(stderr)))
		fprintf(stderr, "%s", str);
#endif
}

static uint64_t get_ns()
{
#ifdef MEASURE_TIMING
	struct timespec tp { 0 };

	if (clock_gettime(USE_CLOCK, &tp) == -1) {
		perror("clock_gettime");
		return 0;
	}

	return tp.tv_sec * 1000ll * 1000ll * 1000ll + tp.tv_nsec;
#else
	return 0;
#endif
}

uint64_t global_start_ts = get_ns();

std::atomic<std::uint64_t> items_idx { 0 };
lock_trace_item_t *items = nullptr;

std::atomic<std::uint64_t> cnt_mutex_trylock { 0 };
std::atomic<std::uint64_t> cnt_rwlock_try_rdlock { 0 };
std::atomic<std::uint64_t> cnt_rwlock_try_timedrdlock { 0 };
std::atomic<std::uint64_t> cnt_rwlock_try_wrlock { 0 };
std::atomic<std::uint64_t> cnt_rwlock_try_timedwrlock { 0 };

// assuming atomic 8-byte pointer updates
typedef int (* org_pthread_mutex_lock)(pthread_mutex_t *mutex);
org_pthread_mutex_lock org_pthread_mutex_lock_h = nullptr;

typedef int (* org_pthread_mutex_trylock)(pthread_mutex_t *mutex);
org_pthread_mutex_trylock org_pthread_mutex_trylock_h = nullptr;

typedef int (* org_pthread_mutex_unlock)(pthread_mutex_t *mutex);
org_pthread_mutex_unlock org_pthread_mutex_unlock_h = nullptr;

typedef int (* org_pthread_mutex_init)(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr);
org_pthread_mutex_init org_pthread_mutex_init_h = nullptr;

typedef int (* org_pthread_mutex_destroy)(pthread_mutex_t *mutex);
org_pthread_mutex_destroy org_pthread_mutex_destroy_h = nullptr;

typedef int (* org_pthread_exit)(void *retval);
org_pthread_exit org_pthread_exit_h = nullptr;

typedef int (* org_pthread_setname_np)(pthread_t thread, const char *name);
org_pthread_setname_np org_pthread_setname_np_h = nullptr;

typedef pid_t (* org_fork)(void);
org_fork org_fork_h = nullptr;

typedef int (* org_pthread_rwlock_rdlock)(pthread_rwlock_t *rwlock);
org_pthread_rwlock_rdlock org_pthread_rwlock_rdlock_h = nullptr;

typedef int (* org_pthread_rwlock_tryrdlock)(pthread_rwlock_t *rwlock);
org_pthread_rwlock_tryrdlock org_pthread_rwlock_tryrdlock_h = nullptr;

typedef int (* org_pthread_rwlock_timedrdlock)(pthread_rwlock_t *rwlock, const struct timespec *abstime);
org_pthread_rwlock_timedrdlock org_pthread_rwlock_timedrdlock_h = nullptr;

typedef int (* org_pthread_rwlock_wrlock)(pthread_rwlock_t *rwlock);
org_pthread_rwlock_wrlock org_pthread_rwlock_wrlock_h = nullptr;

typedef int (* org_pthread_rwlock_trywrlock)(pthread_rwlock_t *rwlock);
org_pthread_rwlock_trywrlock org_pthread_rwlock_trywrlock_h = nullptr;

typedef int (* org_pthread_rwlock_timedwrlock)(pthread_rwlock_t *rwlock, const struct timespec *abstime);
org_pthread_rwlock_timedwrlock org_pthread_rwlock_timedwrlock_h = nullptr;

typedef int (* org_pthread_rwlock_unlock)(pthread_rwlock_t *rwlock);
org_pthread_rwlock_unlock org_pthread_rwlock_unlock_h = nullptr;

typedef int (* org_pthread_rwlock_destroy)(pthread_rwlock_t *rwlock);
org_pthread_rwlock_destroy org_pthread_rwlock_destroy_h = nullptr;

typedef int (* org_pthread_rwlock_init)(pthread_rwlock_t *rwlock, const pthread_rwlockattr_t *attr);
org_pthread_rwlock_init org_pthread_rwlock_init_h = nullptr;

std::map<int, std::string> *tid_names = nullptr;
pthread_rwlock_t tid_names_lock = PTHREAD_RWLOCK_INITIALIZER;

static int _gettid()
{
	return syscall(__NR_gettid);
}

// check that function pointers that are required for 'tid_names'-
// map handling are resolved
static void check_tid_names_lock_functions()
{
	if (unlikely(!org_pthread_rwlock_rdlock_h))
		org_pthread_rwlock_rdlock_h = (org_pthread_rwlock_rdlock)dlsym(RTLD_NEXT, "pthread_rwlock_rdlock");

	if (unlikely(!org_pthread_rwlock_wrlock_h))
		org_pthread_rwlock_wrlock_h = (org_pthread_rwlock_wrlock)dlsym(RTLD_NEXT, "pthread_rwlock_wrlock");

	if (unlikely(!org_pthread_rwlock_unlock_h))
		org_pthread_rwlock_unlock_h = (org_pthread_rwlock_unlock)dlsym(RTLD_NEXT, "pthread_rwlock_unlock");
}

static void show_items_buffer_not_allocated_error()
{
	static bool error_shown = false;

	if (!error_shown) {
		color("\033[0;31m");
		fprintf(stderr, "Buffer not (yet) allocated?!\n");
		color("\033[0m");
		error_shown = true;
	}
}

static void print_timestamp()
{
	time_t now = time(nullptr);
	char buffer[26 + 1], *lf;

	ctime_r(&now, buffer);
	lf = strchr(buffer, '\n');
	if (lf)
		*lf = 0x00;

	fprintf(stderr, "%s ", buffer);
}

static void show_items_buffer_full_error()
{
	static bool error_shown = false;

	if (!error_shown) {
		error_shown = true;

		color("\033[0;31m");
		print_timestamp();
		fprintf(stderr, "Trace buffer full\n");
		color("\033[0m");
	}
}

static void show_items_buffer_percent()
{
	color("\033[0;31m");
	print_timestamp();
	fprintf(stderr, "Trace buffer %.2f%% full\n", items_idx * 100.0 / n_records);
	color("\033[0m");
}

static void store_mutex_info(pthread_mutex_t *mutex, lock_action_t la, uint64_t took, const int rc, void *const shallow_backtrace)
{
	if (unlikely(!items)) {
		// when a constructor of some other library already invokes e.g. pthread_mutex_lock
		// before this wrapper has been fully initialized
		show_items_buffer_not_allocated_error();
		return;
	}

	uint64_t cur_idx = items_idx++;

	if (verbose) {
		if (cur_idx % emit_count_threshold == 0)
			show_items_buffer_percent();
	}

	if (likely(cur_idx < n_records)) {
#ifdef WITH_BACKTRACE
#if defined(PREVENT_RECURSION) || defined(SHALLOW_BACKTRACE)
		items[cur_idx].caller[0] = shallow_backtrace;
#else
		backtrace(items[cur_idx].caller, CALLER_DEPTH);
#endif
#endif
		items[cur_idx].lock = mutex;
		items[cur_idx].tid = _gettid();
		items[cur_idx].la = la;
#ifdef MEASURE_TIMING
		items[cur_idx].timestamp = get_ns();
		items[cur_idx].lock_took = took;
#endif

#ifdef STORE_THREAD_NAME
		check_tid_names_lock_functions();

		if ((*org_pthread_rwlock_rdlock_h)(&tid_names_lock) == 0) {
			auto it = tid_names->find(items[cur_idx].tid);
			if (it != tid_names->end())
				memcpy(items[cur_idx].thread_name, it->second.c_str(), std::min(size_t(16), it->second.size() + 1));

			(*org_pthread_rwlock_unlock_h)(&tid_names_lock);
		}
#endif

		items[cur_idx].mutex_innards.__count = mutex->__data.__count;
		items[cur_idx].mutex_innards.__owner = mutex->__data.__owner;
		items[cur_idx].mutex_innards.__kind  = mutex->__data.__kind;
#ifdef __x86_64__
		items[cur_idx].mutex_innards.__spins   = mutex->__data.__spins;
		items[cur_idx].mutex_innards.__elision = mutex->__data.__elision;
#endif

		items[cur_idx].rc = rc;
	}
	else {
		show_items_buffer_full_error();
	}
}

#if (defined(PREVENT_RECURSION) || defined(SHALLOW_BACKTRACE)) && defined(WITH_BACKTRACE)
#define STORE_MUTEX_INFO(a, b, c, d) store_mutex_info(a, b, c, d, __builtin_return_address(0))
#else
#define STORE_MUTEX_INFO(a, b, c, d) store_mutex_info(a, b, c, d, nullptr) 
#endif

pid_t fork(void)
{
	if (unlikely(!org_fork_h))
		org_fork_h = (org_fork)dlsym(RTLD_NEXT, "fork");

	fork_warning = true;

	return (*org_fork_h)();
}

#ifdef CAPTURE_PTHREAD_EXIT
void pthread_exit(void *retval)
{
	if (likely(items != nullptr)) {
		uint64_t cur_idx = items_idx++;

		if (likely(cur_idx < n_records)) {
			items[cur_idx].lock = nullptr;
			items[cur_idx].tid = _gettid();
			items[cur_idx].la = a_thread_clean;
#ifdef WITH_TIMESTAMP
			items[cur_idx].timestamp = get_ns();
#endif
		}
		else {
			show_items_buffer_full_error();
		}
	}

#ifdef CAPTURE_PTHREAD_EXIT
	if (unlikely(!org_pthread_exit_h))
		org_pthread_exit_h = (org_pthread_exit)dlsym(RTLD_NEXT, "pthread_exit");
#endif

#ifdef STORE_THREAD_NAME
	check_tid_names_lock_functions();

	if ((*org_pthread_rwlock_wrlock_h)(&tid_names_lock) == 0) {
		tid_names->erase(_gettid());

		(*org_pthread_rwlock_unlock_h)(&tid_names_lock);
	}
#endif

	(*org_pthread_exit_h)(retval);

	color("\033[0;31m");
	fprintf(stderr, "pthread_exit did not stop thread!\n");
	color("\033[0m");

	for(;;)
		sleep(86400);
}
#endif

int pthread_mutex_lock(pthread_mutex_t *mutex)
{
	if (unlikely(!org_pthread_mutex_lock_h))
		org_pthread_mutex_lock_h = (org_pthread_mutex_lock)dlsym(RTLD_NEXT, "pthread_mutex_lock");

#ifdef MUTEX_SANITY_CHECKS
	if (mutex->__data.__kind < 0 || mutex->__data.__kind > PTHREAD_MUTEX_ADAPTIVE_NP)
		fprintf(stderr, "Mutex %p has unknown type %d (caller: %p)\n", (void *)mutex, mutex->__data.__kind, __builtin_return_address(0));
#endif

	if (enforce_error_check) {
		if (mutex->__data.__kind == PTHREAD_MUTEX_NORMAL || mutex->__data.__kind == PTHREAD_MUTEX_ADAPTIVE_NP || mutex->__data.__kind == PTHREAD_MUTEX_RECURSIVE)
			mutex->__data.__kind = PTHREAD_MUTEX_ERRORCHECK;
	}

	uint64_t start_ts = get_ns();
	int rc = (*org_pthread_mutex_lock_h)(mutex);
	uint64_t end_ts = get_ns();

	STORE_MUTEX_INFO(mutex, a_lock, end_ts - start_ts, rc);

	return rc;
}

void mutex_sanity_check(pthread_mutex_t *const mutex, void *const caller)
{
#ifdef MUTEX_SANITY_CHECKS
	if (mutex->__data.__kind < 0 || mutex->__data.__kind > PTHREAD_MUTEX_ADAPTIVE_NP)
		fprintf(stderr, "Mutex %p has unknown type %d (caller: %p)\n", (void *)mutex, mutex->__data.__kind, caller);

	if (int(mutex->__data.__nusers) < 0)
		fprintf(stderr, "Mutex %p has suspicious '__nusers': %u (caller: %p)\n", (void *)mutex, mutex->__data.__nusers, caller);

	if (mutex->__data.__lock && mutex->__data.__owner == 0)
		fprintf(stderr, "Mutex %p has suspicious '__owner': %u with(caller: %p)\n", (void *)mutex, mutex->__data.__owner, caller);
#endif
}

void rwlock_sanity_check(pthread_rwlock_t *const rwlock, void *const caller)
{
#ifdef RWLOCK_SANITY_CHECKS
#if __GLIBC_PREREQ(2, 30)
	if (int(rwlock->__data.__readers) < 0)
		fprintf(stderr, "rwlock %p has suspicious '__readers': %u (caller: %p)\n", (void *)rwlock, rwlock->__data.__readers, caller);

	if (int(rwlock->__data.__writers) < 0)
		fprintf(stderr, "rwlock %p has suspicious '__writers': %u (caller: %p)\n", (void *)rwlock, rwlock->__data.__writers, caller);

	if (rwlock->__data.__writers > 0 && rwlock->__data.__cur_writer == 0)
		fprintf(stderr, "rwlock %p has suspicious '__cur_writer': %u (caller: %p)\n", (void *)rwlock, rwlock->__data.__cur_writer, caller);
#endif
#endif
}

int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr)
{
	if (unlikely(!org_pthread_mutex_init_h))
		org_pthread_mutex_init_h = (org_pthread_mutex_init)dlsym(RTLD_NEXT, "pthread_mutex_init");

	int rc = (*org_pthread_mutex_init_h)(mutex, attr);
	STORE_MUTEX_INFO(mutex, a_init, 0, rc);

	return rc;
}

int pthread_mutex_destroy(pthread_mutex_t *mutex)
{
	if (unlikely(!org_pthread_mutex_destroy_h))
		org_pthread_mutex_destroy_h = (org_pthread_mutex_destroy)dlsym(RTLD_NEXT, "pthread_mutex_destroy");

	int rc = (*org_pthread_mutex_destroy_h)(mutex);
	STORE_MUTEX_INFO(mutex, a_destroy, 0, rc);

	return rc;
}

int pthread_mutex_trylock(pthread_mutex_t *mutex)
{
	if (unlikely(!org_pthread_mutex_trylock_h))
		org_pthread_mutex_trylock_h = (org_pthread_mutex_trylock)dlsym(RTLD_NEXT, "pthread_mutex_trylock");

	cnt_mutex_trylock++;

	mutex_sanity_check(mutex, __builtin_return_address(0));

	int rc = (*org_pthread_mutex_trylock_h)(mutex);

	STORE_MUTEX_INFO(mutex, a_lock, 0, rc);

	return rc;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
	if (unlikely(!org_pthread_mutex_unlock_h))
		org_pthread_mutex_unlock_h = (org_pthread_mutex_unlock)dlsym(RTLD_NEXT, "pthread_mutex_unlock");

	mutex_sanity_check(mutex, __builtin_return_address(0));

	int rc = (*org_pthread_mutex_unlock_h)(mutex);

	STORE_MUTEX_INFO(mutex, a_unlock, 0, rc);

	return rc;
}

static void store_rwlock_info(pthread_rwlock_t *rwlock, lock_action_t la, uint64_t took, const int rc, void *const shallow_backtrace)
{
	if (unlikely(!items)) {
		show_items_buffer_not_allocated_error();
		return;
	}

	uint64_t cur_idx = items_idx++;

	if (verbose) {
		if (cur_idx % emit_count_threshold == 0)
			show_items_buffer_percent();
	}

	if (likely(cur_idx < n_records)) {
#ifdef WITH_BACKTRACE
#if defined(PREVENT_RECURSION) || defined(SHALLOW_BACKTRACE)
		items[cur_idx].caller[0] = shallow_backtrace;
#else
		backtrace(items[cur_idx].caller, CALLER_DEPTH);
#endif
#endif
		items[cur_idx].lock = rwlock;
		items[cur_idx].tid = _gettid();
		items[cur_idx].la = la;
#ifdef MEASURE_TIMING
		items[cur_idx].timestamp = get_ns();
		items[cur_idx].lock_took = took;
#endif
#ifdef STORE_THREAD_NAME
		check_tid_names_lock_functions();

		if ((*org_pthread_rwlock_rdlock_h)(&tid_names_lock) == 0) {
			auto it = tid_names->find(items[cur_idx].tid);
			if (it != tid_names->end())
				memcpy(items[cur_idx].thread_name, it->second.c_str(), std::min(size_t(16), it->second.size() + 1));

			(*org_pthread_rwlock_unlock_h)(&tid_names_lock);
		}
#endif

#if __GLIBC_PREREQ(2, 30)
		items[cur_idx].rwlock_innards.__readers = rwlock->__data.__readers;
		items[cur_idx].rwlock_innards.__writers = rwlock->__data.__writers;
#else
		items[cur_idx].rwlock_innards.__readers = rwlock->__data.__nr_readers;
#endif
#if defined(__x86_64__) && __GLIBC_PREREQ(2, 30)
		items[cur_idx].rwlock_innards.__cur_writer  = rwlock->__data.__cur_writer;
#else
		items[cur_idx].rwlock_innards.__cur_writer  = 0;
#endif

		items[cur_idx].rc = rc;
	}
	else {
		show_items_buffer_full_error();
	}
}

#if (defined(PREVENT_RECURSION) || defined(SHALLOW_BACKTRACE)) && defined(WITH_BACKTRACE)
#define STORE_RWLOCK_INFO(a, b, c, d) store_rwlock_info(a, b, c, d, __builtin_return_address(0))
#else
#define STORE_RWLOCK_INFO(a, b, c, d) store_rwlock_info(a, b, c, d, nullptr) 
#endif

int pthread_rwlock_init(pthread_rwlock_t *rwlock, const pthread_rwlockattr_t *attr)
{
	if (unlikely(!org_pthread_rwlock_init_h))
		org_pthread_rwlock_init_h = (org_pthread_rwlock_init)dlsym(RTLD_NEXT, "pthread_rwlock_init");

	int rc = (*org_pthread_rwlock_init_h)(rwlock, attr);
	STORE_RWLOCK_INFO(rwlock, a_rw_init, 0, rc);

	return rc;
}

int pthread_rwlock_destroy(pthread_rwlock_t *rwlock)
{
	if (unlikely(!org_pthread_rwlock_destroy_h))
		org_pthread_rwlock_destroy_h = (org_pthread_rwlock_destroy)dlsym(RTLD_NEXT, "pthread_rwlock_destroy");

	int rc = (*org_pthread_rwlock_destroy_h)(rwlock);
	STORE_RWLOCK_INFO(rwlock, a_rw_destroy, 0, rc);

	return rc;
}

int pthread_rwlock_rdlock(pthread_rwlock_t *rwlock)
{
	if (unlikely(!org_pthread_rwlock_rdlock_h))
		org_pthread_rwlock_rdlock_h = (org_pthread_rwlock_rdlock)dlsym(RTLD_NEXT, "pthread_rwlock_rdlock");

	rwlock_sanity_check(rwlock, __builtin_return_address(0));

	uint64_t start_ts = get_ns();
	int rc = (*org_pthread_rwlock_rdlock_h)(rwlock);
	uint64_t end_ts = get_ns();

	STORE_RWLOCK_INFO(rwlock, a_r_lock, end_ts - start_ts, rc);

	return rc;
}

int pthread_rwlock_tryrdlock(pthread_rwlock_t *rwlock)
{
	if (unlikely(!org_pthread_rwlock_tryrdlock_h))
		org_pthread_rwlock_tryrdlock_h = (org_pthread_rwlock_tryrdlock)dlsym(RTLD_NEXT, "pthread_rwlock_tryrdlock");

	cnt_rwlock_try_rdlock++;

	rwlock_sanity_check(rwlock, __builtin_return_address(0));

	int rc = (*org_pthread_rwlock_tryrdlock_h)(rwlock);

	STORE_RWLOCK_INFO(rwlock, a_r_lock, 0, rc);

	return rc;
}

int pthread_rwlock_timedrdlock(pthread_rwlock_t *rwlock, const struct timespec *abstime)
{
	if (unlikely(!org_pthread_rwlock_timedrdlock_h))
		org_pthread_rwlock_timedrdlock_h = (org_pthread_rwlock_timedrdlock)dlsym(RTLD_NEXT, "pthread_rwlock_timedrdlock");

	cnt_rwlock_try_timedrdlock++;

	rwlock_sanity_check(rwlock, __builtin_return_address(0));

	uint64_t start_ts = get_ns();
	int rc = (*org_pthread_rwlock_timedrdlock_h)(rwlock, abstime);
	uint64_t end_ts = get_ns();

	// TODO seperate a_r_lock for timed locks as they may take quite
	// a bit longer
	STORE_RWLOCK_INFO(rwlock, a_r_lock, end_ts - start_ts, rc);

	return rc;
}

int pthread_rwlock_wrlock(pthread_rwlock_t *rwlock)
{
	if (unlikely(!org_pthread_rwlock_wrlock_h))
		org_pthread_rwlock_wrlock_h = (org_pthread_rwlock_wrlock)dlsym(RTLD_NEXT, "pthread_rwlock_wrlock");

	rwlock_sanity_check(rwlock, __builtin_return_address(0));

	uint64_t start_ts = get_ns();
	int rc = (*org_pthread_rwlock_wrlock_h)(rwlock);
	uint64_t end_ts = get_ns();

	STORE_RWLOCK_INFO(rwlock, a_w_lock, end_ts - start_ts, rc);

	return rc;
}

int pthread_rwlock_trywrlock(pthread_rwlock_t *rwlock)
{
	if (unlikely(!org_pthread_rwlock_trywrlock_h))
		org_pthread_rwlock_trywrlock_h = (org_pthread_rwlock_trywrlock)dlsym(RTLD_NEXT, "pthread_rwlock_trywrlock");

	cnt_rwlock_try_wrlock++;

	rwlock_sanity_check(rwlock, __builtin_return_address(0));

	int rc = (*org_pthread_rwlock_trywrlock_h)(rwlock);

	STORE_RWLOCK_INFO(rwlock, a_w_lock, 0, rc);

	return rc;
}

int pthread_rwlock_timedwrlock(pthread_rwlock_t *rwlock, const struct timespec *abstime)
{
	if (unlikely(!org_pthread_rwlock_timedwrlock_h))
		org_pthread_rwlock_timedwrlock_h = (org_pthread_rwlock_timedwrlock)dlsym(RTLD_NEXT, "pthread_rwlock_timedwrlock");

	cnt_rwlock_try_timedwrlock++;

	rwlock_sanity_check(rwlock, __builtin_return_address(0));

	uint64_t start_ts = get_ns();
	int rc = (*org_pthread_rwlock_timedwrlock_h)(rwlock, abstime);
	uint64_t end_ts = get_ns();

	STORE_RWLOCK_INFO(rwlock, a_w_lock, end_ts - start_ts, rc);

	return rc;
}

int pthread_rwlock_unlock(pthread_rwlock_t *rwlock)
{
	if (unlikely(!org_pthread_rwlock_unlock_h))
		org_pthread_rwlock_unlock_h = (org_pthread_rwlock_unlock)dlsym(RTLD_NEXT, "pthread_rwlock_unlock");

	rwlock_sanity_check(rwlock, __builtin_return_address(0));

	int rc = (*org_pthread_rwlock_unlock_h)(rwlock);

	STORE_RWLOCK_INFO(rwlock, a_rw_unlock, 0, rc);

	return rc;
}

int pthread_setname_np(pthread_t thread, const char *name)
{
#ifdef STORE_THREAD_NAME
	if (likely(name != nullptr)) {
		check_tid_names_lock_functions();

		if ((*org_pthread_rwlock_wrlock_h)(&tid_names_lock) == 0) {
			tid_names->emplace(_gettid(), name);

			(*org_pthread_rwlock_unlock_h)(&tid_names_lock);
		}
	}
#endif

	if (unlikely(!org_pthread_setname_np_h))
		org_pthread_setname_np_h = (org_pthread_setname_np)dlsym(RTLD_NEXT, "pthread_setname_np");

	return (*org_pthread_setname_np_h)(thread, name);
}

void __attribute__ ((constructor)) start_lock_tracing()
{
	color("\033[0;31m");

	fprintf(stderr, "Lock tracer starting... (structure size: %zu bytes)\n", sizeof(lock_trace_item_t));

	struct rlimit rlim { 0, 0 };
	if (getrlimit(RLIMIT_CORE, &rlim) == -1)
		perror("getrlimit(RLIMIT_CORE) failed");
	else if (rlim.rlim_max == 0 || rlim.rlim_cur == 0)
		fprintf(stderr, "NOTE: core-files have been disabled! You may want to re-run after invoking \"ulimit -c unlimited\".\n");

	const char *env_n_records = getenv("TRACE_N_RECORDS");
	if (env_n_records) {
		n_records = atoll(env_n_records);

		emit_count_threshold = n_records / 10;
	}

	verbose = getenv("TRACE_VERBOSE") != nullptr;
	if (verbose)
		fprintf(stderr, "Verbose tracing enabled\n");

	enforce_error_check = getenv("ENFORCE_ERR_CHK") != nullptr;
	if (enforce_error_check)
		fprintf(stderr, "Replacing all mutexes by error-checking mutexes\n");

	fprintf(stderr, "Tracing max. %zu records\n", n_records);

	asprintf(&data_filename, "measurements-%d.dat", getpid());

	mmap_fd = open(data_filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (mmap_fd == -1) {
		fprintf(stderr, "ERROR: cannot create data file %s: %s\n", data_filename, strerror(errno));
		color("\033[0m");
		_exit(1);
	}

	length = n_records * sizeof(lock_trace_item_t);

	if (ftruncate(mmap_fd, length) == -1) {
		fprintf(stderr, "ERROR: problem reserving space on disk: %s\n", strerror(errno));
		color("\033[0m");
		_exit(1);
	}

#ifdef PREALLOCATE
	items = (lock_trace_item_t *)mmap(nullptr, length, PROT_WRITE | PROT_READ, MAP_SHARED | MAP_POPULATE, mmap_fd, 0);
#else
	items = (lock_trace_item_t *)mmap(nullptr, length, PROT_WRITE | PROT_READ, MAP_SHARED, mmap_fd, 0);
#endif

	if (items == MAP_FAILED) {
		fprintf(stderr, "ERROR: cannot allocate %lu bytes of memory (reduce with the \"TRACE_N_RECORDS\" environment variable): %s\n", length, strerror(errno));
		color("\033[0m");
		_exit(1);
	}

	if (posix_madvise(items, length, POSIX_MADV_SEQUENTIAL) == -1)
		perror("madvise");

	tid_names = new std::map<int, std::string>();

	if (!tid_names) {
		fprintf(stderr, "ERROR: cannot allocate map for \"TID - thread-name\" mapping\n");
		color("\033[0m");
		_exit(1);
	}

	color("\033[0m");
}

static void emit_key_value(json_t *const tgt, const char *key, const char *value)
{
	json_object_set(tgt, key, json_string(value));
}

static void emit_key_value(json_t *const tgt, const char *key, const uint64_t value)
{
	json_object_set(tgt, key, json_integer(value));
}

void exit(int status)
{
	exited = true;
	uint64_t end_ts = get_ns();

	color("\033[0;31m");

	unsigned long count = items_idx;
	fprintf(stderr, "Lock tracer terminating with %lu records (path: %s, %zu bytes)\n", count, get_current_dir_name(), length);

	if (msync(items, length, MS_SYNC) == -1)
		fprintf(stderr, "Problem pushing data to disk: %s\n", strerror(errno));

	munmap(items, length);  // TODO error checking

	close(mmap_fd);

	if (!items) {
		fprintf(stderr, "No items recorded yet\n");
		color("\033[0m");
	}
	else {
		char *file_name = nullptr;
		if (asprintf(&file_name, "dump.dat.%d", getpid()) == -1) {
			fprintf(stderr, "asprintf failed: using \"dump.dat\" as filename\n");
			file_name = strdup("dump.dat");
		}

		fprintf(stderr, "Trace file (load with '-t' in analyze.py): %s\n", file_name);

		color("\033[0m");

		FILE *fh = fopen(file_name, "w");

		free(file_name);

		if (!fh)
			fh = stderr;

		json_t *obj = json_object();

		char hostname[HOST_NAME_MAX + 1];
		gethostname(hostname, sizeof hostname);

		emit_key_value(obj, "hostname", hostname);

		emit_key_value(obj, "start_ts", global_start_ts);

		emit_key_value(obj, "end_ts", end_ts);

		emit_key_value(obj, "fork_warning", fork_warning);

		emit_key_value(obj, "n_procs", get_nprocs());

		pid_t pid = getpid();
		emit_key_value(obj, "pid", pid);

		int s = sched_getscheduler(pid);
		if (s == SCHED_OTHER)
			emit_key_value(obj, "scheduler", "sched-other");
		else if (s == SCHED_BATCH)
			emit_key_value(obj, "scheduler", "sched-batch");
		else if (s == SCHED_IDLE)
			emit_key_value(obj, "scheduler", "sched-idle");
		else if (s == SCHED_FIFO)
			emit_key_value(obj, "scheduler", "sched-fifo");
		else if (s == SCHED_RR)
			emit_key_value(obj, "scheduler", "sched-rr");
		else
			emit_key_value(obj, "scheduler", "unknown");

		emit_key_value(obj, "mutex_type_normal", PTHREAD_MUTEX_NORMAL);
		emit_key_value(obj, "mutex_type_recursive", PTHREAD_MUTEX_RECURSIVE);
		emit_key_value(obj, "mutex_type_errorcheck", PTHREAD_MUTEX_ERRORCHECK);
		emit_key_value(obj, "mutex_type_adaptive", PTHREAD_MUTEX_ADAPTIVE_NP);

		char exe_name[PATH_MAX] = { 0 };
		if (readlink("/proc/self/exe", exe_name, sizeof(exe_name) - 1) == -1) {
			color("\033[0;31m");
			fprintf(stderr, "readlink(/proc/self/exe) failed: %s\n", strerror(errno));
			color("\033[0m");
		}

		emit_key_value(obj, "exe_name", exe_name);

		emit_key_value(obj, "measurements", data_filename);

		emit_key_value(obj, "cnt_mutex_trylock", cnt_mutex_trylock);
		emit_key_value(obj, "cnt_rwlock_try_rdlock", cnt_rwlock_try_rdlock);
		emit_key_value(obj, "cnt_rwlock_try_timedrdlock", cnt_rwlock_try_timedrdlock);
		emit_key_value(obj, "cnt_rwlock_try_wrlock", cnt_rwlock_try_wrlock);
		emit_key_value(obj, "cnt_rwlock_try_timedwrlock", cnt_rwlock_try_timedwrlock);

		// Copy, in case a thread is still running and adding new records: a for-loop
		// on 'items_idx' might run longer than intended and even emit garbage.
		uint64_t n_rec_inserted = items_idx;

		if (n_rec_inserted > n_records)
			n_rec_inserted = n_records;

		emit_key_value(obj, "n_records", n_rec_inserted);
		emit_key_value(obj, "n_records_max", n_records);

		fprintf(fh, "%s\n", json_dumps(obj, JSON_COMPACT));
		json_decref(obj);

		if (fh != stderr) {
			fclose(fh);

			sync();
		}
	}

	// make sure no entries are added by threads that are
	// still running; next statement unallocates the mmap()ed
	// memory
	items_idx = n_records;

	delete tid_names;

	// dump core
	color("\033[0;31m");
	fprintf(stderr, "Dumping core...\n");
	color("\033[0m");

	fflush(nullptr);

	signal(SIGABRT, SIG_DFL);
	abort();
}

void __attribute__ ((destructor)) stop_lock_tracing()
{
	if (!exited)
		exit(0);
}
