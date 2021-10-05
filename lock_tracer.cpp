// (C) 2021 by folkert@vanheusden.com
// released under GPL v3.0

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <atomic>
#include <dlfcn.h>
#include <errno.h>
#include <execinfo.h>
#include <jansson.h>
#include <limits.h>
#include <map>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bits/pthreadtypes.h>
#include <bits/struct_mutex.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/types.h>

#if JSON_INTEGER_IS_LONG_LONG
#else
	#error jansson should have been compiled with JSON_INTEGER_IS_LONG_LONG
#endif

//// YOU MAY NEED TO CHANGE THIS ////

#define WITH_BACKTRACE

#define WITH_TIMESTAMP

#define CALLER_DEPTH 8

#define PREVENT_RECURSION  // required at least on RHEL and Fedora

#define CAPTURE_PTHREAD_EXIT

#define STORE_THREAD_NAME

#define WITH_COLORS

#define USE_CLOCK CLOCK_MONOTONIC

/////////////////////////////////////

#ifndef __linux__
#warning This program may only work correctly on Linux.
#endif

#define likely(x)       __builtin_expect((x), 1)
#define unlikely(x)     __builtin_expect((x), 0)

uint64_t n_records = 16777216;
size_t length = 0;

bool fork_warning = false;

void color(const char *str)
{
#ifdef WITH_COLORS
	if (isatty(fileno(stderr)))
		fprintf(stderr, "%s", str);
#endif
}

uint64_t get_us()
{
	struct timespec tp { 0 };

	if (clock_gettime(USE_CLOCK, &tp) == -1) {
		perror("clock_gettime");
		return 0;
	}

        return tp.tv_sec * 1000l * 1000l + tp.tv_nsec / 1000;
}

uint64_t start_ts = get_us();

typedef enum { a_lock, a_unlock, a_thread_clean, a_deadlock, a_r_lock, a_w_lock, a_rw_unlock } lock_action_t;

typedef struct {
#ifdef WITH_BACKTRACE
	void *caller[CALLER_DEPTH];
#endif
	void *lock;
	int tid;
	lock_action_t la; 
	uint64_t timestamp;
#ifdef STORE_THREAD_NAME
	// the one in linux is said to be max. 16 characters including 0x00 (pthread_setname_np)
	char thread_name[16];
#endif
	union {
		struct {
			unsigned int __count;
			int __owner;
			int __kind;
		} mutex_innards;

		struct {
			unsigned int __readers;
			unsigned int __writers;
			int __cur_writer;  // only on __x86_64__
		} rwlock_innards;
	};

	uint64_t lock_took;
} lock_trace_item_t;

std::atomic_uint64_t idx { 0 };
lock_trace_item_t *items = nullptr;

// assuming atomic 8-byte pointer updates
typedef int (* org_pthread_mutex_lock)(pthread_mutex_t *mutex);
org_pthread_mutex_lock org_pthread_mutex_lock_h = nullptr;

typedef int (* org_pthread_mutex_trylock)(pthread_mutex_t *mutex);
org_pthread_mutex_trylock org_pthread_mutex_trylock_h = nullptr;

typedef int (* org_pthread_mutex_unlock)(pthread_mutex_t *mutex);
org_pthread_mutex_unlock org_pthread_mutex_unlock_h = nullptr;

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

std::map<int, std::string> *tid_names = nullptr;

int _gettid()
{
	return syscall(__NR_gettid);
}

thread_local bool prevent_backtrace = false;

void show_items_buffer_not_allocated_error()
{
	static bool error_shown = false;

	if (!error_shown) {
		color("\033[0;31m");
		fprintf(stderr, "Buffer not (yet) allocated?!\n");
		color("\033[0m");
		error_shown = true;
	}
}

void show_items_buffer_full_error()
{
	static bool error_shown = false;

	if (!error_shown) {
		color("\033[0;31m");
		fprintf(stderr, "Trace buffer full\n");
		color("\033[0m");
	}
}

void store_mutex_info(pthread_mutex_t *mutex, lock_action_t la, uint64_t took)
{
	if (unlikely(!items)) {
		// when a constructor of some other library already invokes e.g. pthread_mutex_lock
		// before this wrapper has been fully initialized
		show_items_buffer_not_allocated_error();
		return;
	}

	uint64_t cur_idx = idx++;

	if (likely(cur_idx < n_records)) {
#ifdef WITH_BACKTRACE
		bool get_backtrace = !prevent_backtrace;

		if (likely(get_backtrace)) {
#ifdef PREVENT_RECURSION
			prevent_backtrace = true;
#endif
			backtrace(items[cur_idx].caller, CALLER_DEPTH);
#ifdef PREVENT_RECURSION
			prevent_backtrace = false;
#endif
		}
#endif
		items[cur_idx].lock = mutex;
		items[cur_idx].tid = _gettid();
		items[cur_idx].la = la;
#ifdef WITH_TIMESTAMP
		items[cur_idx].timestamp = get_us();
#endif
#ifdef STORE_THREAD_NAME
		if (likely(tid_names != nullptr)) {
			auto it = tid_names->find(items[cur_idx].tid);
			if (it != tid_names->end())
				memcpy(items[cur_idx].thread_name, it->second.c_str(), std::min(size_t(16), it->second.size() + 1));
		}
#endif

		items[cur_idx].mutex_innards.__count = mutex->__data.__count;
		items[cur_idx].mutex_innards.__owner = mutex->__data.__owner;
		items[cur_idx].mutex_innards.__kind  = mutex->__data.__kind;

		items[cur_idx].lock_took = took;
	}
	else {
		show_items_buffer_full_error();
	}
}

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
	prevent_backtrace = true;

	if (likely(items != nullptr)) {
		uint64_t cur_idx = idx++;

		if (likely(cur_idx < n_records)) {
			items[cur_idx].lock = nullptr;
			items[cur_idx].tid = _gettid();
			items[cur_idx].la = a_thread_clean;
#ifdef WITH_TIMESTAMP
			items[cur_idx].timestamp = get_us();
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

	if (likely(tid_names != nullptr))
		tid_names->erase(_gettid());

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

	uint64_t start_ts = get_us();
	int rc = (*org_pthread_mutex_lock_h)(mutex);
	uint64_t end_ts = get_us();

	if (likely(rc == 0))
		store_mutex_info(mutex, a_lock, end_ts - start_ts);
	else if (rc == EDEADLK)
		store_mutex_info(mutex, a_deadlock, 0);

	return rc;
}

int pthread_mutex_trylock(pthread_mutex_t *mutex)
{
	if (unlikely(!org_pthread_mutex_trylock_h))
		org_pthread_mutex_trylock_h = (org_pthread_mutex_trylock)dlsym(RTLD_NEXT, "pthread_mutex_trylock");

	int rc = (*org_pthread_mutex_trylock_h)(mutex);

	if (likely(rc == 0))
		store_mutex_info(mutex, a_lock, 0);
	else if (rc == EDEADLK)
		store_mutex_info(mutex, a_deadlock, 0);

	return rc;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
	if (unlikely(!org_pthread_mutex_unlock_h))
		org_pthread_mutex_unlock_h = (org_pthread_mutex_unlock)dlsym(RTLD_NEXT, "pthread_mutex_unlock");

	int rc = (*org_pthread_mutex_unlock_h)(mutex);

	if (likely(rc == 0))
		store_mutex_info(mutex, a_unlock, 0);
	else if (rc == EDEADLK)
		store_mutex_info(mutex, a_deadlock, 0);

	return rc;
}

void store_rwlock_info(pthread_rwlock_t *rwlock, lock_action_t la, uint64_t took)
{
	if (unlikely(!items)) {
		show_items_buffer_not_allocated_error();
		return;
	}

	uint64_t cur_idx = idx++;

	if (likely(cur_idx < n_records)) {
#ifdef WITH_BACKTRACE
		bool get_backtrace = !prevent_backtrace;

		if (likely(get_backtrace)) {
#ifdef PREVENT_RECURSION
			prevent_backtrace = true;
#endif
			backtrace(items[cur_idx].caller, CALLER_DEPTH);
#ifdef PREVENT_RECURSION
			prevent_backtrace = false;
#endif
		}
#endif
		items[cur_idx].lock = rwlock;
		items[cur_idx].tid = _gettid();
		items[cur_idx].la = la;
#ifdef WITH_TIMESTAMP
		items[cur_idx].timestamp = get_us();
#endif
#ifdef STORE_THREAD_NAME
		if (likely(tid_names != nullptr)) {
			auto it = tid_names->find(items[cur_idx].tid);
			if (it != tid_names->end())
				memcpy(items[cur_idx].thread_name, it->second.c_str(), std::min(size_t(16), it->second.size() + 1));
		}
#endif

		items[cur_idx].rwlock_innards.__readers = rwlock->__data.__readers;
		items[cur_idx].rwlock_innards.__writers = rwlock->__data.__writers;
#if __x86_64__
		items[cur_idx].rwlock_innards.__cur_writer  = rwlock->__data.__cur_writer;
#else
		items[cur_idx].rwlock_innards.__cur_writer  = 0;
#endif

		items[cur_idx].lock_took = took;
	}
	else {
		show_items_buffer_full_error();
	}
}

int pthread_rwlock_rdlock(pthread_rwlock_t *rwlock)
{
	if (unlikely(!org_pthread_rwlock_rdlock_h))
		org_pthread_rwlock_rdlock_h = (org_pthread_rwlock_rdlock)dlsym(RTLD_NEXT, "pthread_rwlock_rdlock");

	uint64_t start_ts = get_us();
	int rc = (*org_pthread_rwlock_rdlock_h)(rwlock);
	uint64_t end_ts = get_us();

	if (likely(rc == 0))
		store_rwlock_info(rwlock, a_r_lock, end_ts - start_ts);
	else if (rc == EDEADLK)
		store_rwlock_info(rwlock, a_deadlock, 0);

	return rc;
}

int pthread_rwlock_tryrdlock(pthread_rwlock_t *rwlock)
{
	if (unlikely(!org_pthread_rwlock_tryrdlock_h))
		org_pthread_rwlock_tryrdlock_h = (org_pthread_rwlock_tryrdlock)dlsym(RTLD_NEXT, "pthread_rwlock_tryrdlock");

	uint64_t start_ts = get_us();
	int rc = (*org_pthread_rwlock_tryrdlock_h)(rwlock);
	uint64_t end_ts = get_us();

	if (likely(rc == 0))
		store_rwlock_info(rwlock, a_r_lock, end_ts - start_ts);
	else if (rc == EDEADLK)
		store_rwlock_info(rwlock, a_deadlock, 0);

	return rc;
}

int pthread_rwlock_timedrdlock(pthread_rwlock_t *rwlock, const struct timespec *abstime)
{
	if (unlikely(!org_pthread_rwlock_timedrdlock_h))
		org_pthread_rwlock_timedrdlock_h = (org_pthread_rwlock_timedrdlock)dlsym(RTLD_NEXT, "pthread_rwlock_timedrdlock");

	uint64_t start_ts = get_us();
	int rc = (*org_pthread_rwlock_timedrdlock_h)(rwlock, abstime);
	uint64_t end_ts = get_us();

	// TODO seperate a_r_lock for timed locks as they may take quite
	// a bit longer
	if (likely(rc == 0))
		store_rwlock_info(rwlock, a_r_lock, end_ts - start_ts);
	else if (rc == EDEADLK)
		store_rwlock_info(rwlock, a_deadlock, 0);

	return rc;
}

int pthread_rwlock_wrlock(pthread_rwlock_t *rwlock)
{
	if (unlikely(!org_pthread_rwlock_wrlock_h))
		org_pthread_rwlock_wrlock_h = (org_pthread_rwlock_wrlock)dlsym(RTLD_NEXT, "pthread_rwlock_wrlock");

	uint64_t start_ts = get_us();
	int rc = (*org_pthread_rwlock_wrlock_h)(rwlock);
	uint64_t end_ts = get_us();

	if (likely(rc == 0))
		store_rwlock_info(rwlock, a_w_lock, end_ts - start_ts);
	else if (rc == EDEADLK)
		store_rwlock_info(rwlock, a_deadlock, 0);

	return rc;
}

int pthread_rwlock_timedwrlock(pthread_rwlock_t *rwlock, const struct timespec *abstime)
{
	if (unlikely(!org_pthread_rwlock_timedwrlock_h))
		org_pthread_rwlock_timedwrlock_h = (org_pthread_rwlock_timedwrlock)dlsym(RTLD_NEXT, "pthread_rwlock_timedwrlock");

	uint64_t start_ts = get_us();
	int rc = (*org_pthread_rwlock_timedwrlock_h)(rwlock, abstime);
	uint64_t end_ts = get_us();

	if (likely(rc == 0))
		store_rwlock_info(rwlock, a_w_lock, end_ts - start_ts);
	else if (rc == EDEADLK)
		store_rwlock_info(rwlock, a_deadlock, 0);

	return rc;
}

int pthread_rwlock_unlock(pthread_rwlock_t *rwlock)
{
	if (unlikely(!org_pthread_rwlock_unlock_h))
		org_pthread_rwlock_unlock_h = (org_pthread_rwlock_unlock)dlsym(RTLD_NEXT, "pthread_rwlock_unlock");

	int rc = (*org_pthread_rwlock_unlock_h)(rwlock);

	if (likely(rc == 0))
		store_rwlock_info(rwlock, a_rw_unlock, 0);
	else if (rc == EDEADLK)
		store_rwlock_info(rwlock, a_deadlock, 0);

	return rc;
}

int pthread_setname_np(pthread_t thread, const char *name)
{
	if (tid_names && name)
		tid_names->emplace(_gettid(), name);

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
	if (env_n_records)
		n_records = atoll(env_n_records);

	fprintf(stderr, "Tracing max. %zu records\n", n_records);

	length = n_records * sizeof(lock_trace_item_t);
	items = (lock_trace_item_t *)mmap(nullptr, length, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

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

void emit_key_value(FILE *fh, const char *key, const char *value)
{
	json_t *obj = json_object();
	json_object_set(obj, "type", json_string("meta"));
	json_object_set(obj, key, json_string(value));

	fprintf(fh, "%s\n", json_dumps(obj, JSON_COMPACT));

	json_decref(obj);
}

void emit_key_value(FILE *fh, const char *key, const uint64_t value)
{
	json_t *obj = json_object();
	json_object_set(obj, "type", json_string("meta"));
	json_object_set(obj, key, json_integer(value));

	fprintf(fh, "%s\n", json_dumps(obj, JSON_COMPACT));

	json_decref(obj);
}

void exit(int status)
{
	uint64_t end_ts = get_us();

	color("\033[0;31m");
	fprintf(stderr, "Lock tracer terminating... (path: %s)\n", get_current_dir_name());

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

		char hostname[HOST_NAME_MAX + 1];
		gethostname(hostname, sizeof hostname);

		emit_key_value(fh, "hostname", hostname);

		emit_key_value(fh, "start_ts", start_ts);

		emit_key_value(fh, "end_ts", end_ts);

		emit_key_value(fh, "fork_warning", fork_warning);

		emit_key_value(fh, "n_procs", get_nprocs());

		emit_key_value(fh, "pid", getpid());

		emit_key_value(fh, "mutex_type_normal", PTHREAD_MUTEX_NORMAL);
		emit_key_value(fh, "mutex_type_recursive", PTHREAD_MUTEX_RECURSIVE);
		emit_key_value(fh, "mutex_type_errorcheck", PTHREAD_MUTEX_ERRORCHECK);

		char exe_name[PATH_MAX] = { 0 };
		if (readlink("/proc/self/exe", exe_name, sizeof(exe_name) - 1) == -1) {
			color("\033[0;31m");
			fprintf(stderr, "readlink(/proc/self/exe) failed: %s\n", strerror(errno));
			color("\033[0m");
		}

		emit_key_value(fh, "exe_name", exe_name);

		char caller_str[512];

		// Copy, in case a thread is still running and adding new records: a for-loop
		// on 'idx' might run longer than intended and even emit garbage.
		uint64_t n_rec_inserted = idx;

		if (n_rec_inserted > n_records)
			n_rec_inserted = n_records;

		emit_key_value(fh, "n_records", n_rec_inserted);
		emit_key_value(fh, "n_records_max", n_records);

		json_t *m_obj = json_object();
		json_object_set(m_obj, "type", json_string("marker"));
		fprintf(fh, "%s\n", json_dumps(m_obj, JSON_COMPACT));
		json_decref(m_obj);

		for(uint64_t i = 0; i<n_rec_inserted; i++) {
			caller_str[0] = 0x00;

#ifndef WITH_TIMESTAMP
			items[i].timestamp = 0;
#endif

#ifdef WITH_BACKTRACE
			for(int j=0; j<CALLER_DEPTH; j++)
				sprintf(&caller_str[strlen(caller_str)], "%p,", items[i].caller[j]);
#endif

			const char *action_name = "?";
			bool rw_lock = false;

			if (items[i].la == a_lock)
				action_name = "lock";
			else if (items[i].la == a_unlock)
				action_name = "unlock";
			else if (items[i].la == a_thread_clean)
				action_name = "tclean";
			else if (items[i].la == a_deadlock)
				action_name = "deadlock";
			else if (items[i].la == a_r_lock)
				action_name = "readlock", rw_lock = true;
			else if (items[i].la == a_w_lock)
				action_name = "writelock", rw_lock = true;
			else if (items[i].la == a_rw_unlock)
				action_name = "rwunlock", rw_lock = true;

#ifdef STORE_THREAD_NAME
			char *name = items[i].thread_name;
			int len = strlen(name);

			for(int i=0; i<len; i++) {
				if (name[i] < 33 || name[i] > 126)
					name[i] = '_';
			}
#else
			char name[16] = { 0 };
#endif

			if (name[0] == 0x00) {
				name[0] = '?';
				name[1] = 0x00;
			}

			json_t *obj = json_object();
			json_object_set(obj, "type", json_string("data"));
			json_object_set(obj, "t", json_integer(i));
			json_object_set(obj, "lock", json_integer((long long unsigned int)items[i].lock));
			json_object_set(obj, "tid", json_integer(items[i].tid));
			json_object_set(obj, "action", json_string(action_name));
			json_object_set(obj, "caller", json_string(caller_str));
			json_object_set(obj, "timestamp", json_integer(items[i].timestamp));
			json_object_set(obj, "thread_name", json_string(name));
			json_object_set(obj, "lock_took", json_integer(items[i].lock_took));

			if (rw_lock) {
				json_object_set(obj, "rwlock_readers", json_integer(items[i].rwlock_innards.__readers));
				json_object_set(obj, "rwlock_writers", json_integer(items[i].rwlock_innards.__writers));
				json_object_set(obj, "cur_writer",     json_integer(items[i].rwlock_innards.__cur_writer));
			}
			else {
				json_object_set(obj, "mutex_count", json_integer(items[i].mutex_innards.__count));
				json_object_set(obj, "mutex_owner", json_integer(items[i].mutex_innards.__owner));
				json_object_set(obj, "mutex_kind",  json_integer(items[i].mutex_innards.__kind));
			}

			fprintf(fh, "%s\n", json_dumps(obj, JSON_COMPACT));
			json_decref(obj);
		}

		if (fh != stderr) {
			fsync(fileno(fh));
			fclose(fh);

			sync();
		}
	}

	fflush(nullptr);

	// make sure no entries are added by threads that are
	// still running; next statement unallocates the mmap()ed
	// memory
	idx = n_records;

	munmap(items, length);

	delete tid_names;

	assert(0);
}

void __attribute__ ((destructor)) stop_lock_tracing()
{
	exit(0);
}
