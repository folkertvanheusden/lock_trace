// (C) 2021 by folkert@vanheusden.com
// released under GPL v3.0

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <atomic>
#include <dlfcn.h>
#include <execinfo.h>
#include <map>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>

//// YOU MAY NEED TO CHANGE THIS ////

#define WITH_BACKTRACE

#define WITH_TIMESTAMP

#define CALLER_DEPTH 8

#define BUFFER_SIZE 16777216  // in number of items

#define PREVENT_RECURSION  // required at least on RHEL and Fedora

#define CAPTURE_PTHREAD_EXIT

#define STORE_THREAD_NAME

/////////////////////////////////////

#ifndef __linux__
#warning This program may only work correctly on Linux.
#endif

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

uint64_t get_us()
{
        struct timeval tv = { 0, 0 };
        gettimeofday(&tv, NULL);

        return tv.tv_sec * 1000l * 1000l + tv.tv_usec;
}

typedef enum { a_lock, a_unlock, a_thread_clean, a_deadlock } lock_action_t;

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
} lock_trace_item_t;

std::atomic_uint64_t idx { 0 };
lock_trace_item_t *items = nullptr;

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

std::map<int, std::string> *tid_names = nullptr;

int _gettid()
{
	return syscall(__NR_gettid);
}

thread_local bool prevent_backtrace = false;

void store_mutex_info(pthread_mutex_t *mutex, lock_action_t la)
{
	if (unlikely(!items)) {
		// when a constructor of some other library already invokes e.g. pthread_mutex_lock
		// before this wrapper has been fully initialized
		static bool error_shown = false;

		if (!error_shown) {
			fprintf(stderr, "Buffer not (yet) allocated?!\n");
			error_shown = true;
		}

		return;
	}

	uint64_t cur_idx = idx++;

	if (likely(cur_idx < BUFFER_SIZE)) {
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
	}
}

#ifdef CAPTURE_PTHREAD_EXIT
void pthread_exit(void *retval)
{
	prevent_backtrace = true;

	if (likely(items != nullptr)) {
		uint64_t cur_idx = idx++;

		if (likely(cur_idx < BUFFER_SIZE)) {
			items[cur_idx].lock = nullptr;
			items[cur_idx].tid = _gettid();
			items[cur_idx].la = a_thread_clean;
#ifdef WITH_TIMESTAMP
			items[cur_idx].timestamp = get_us();
#endif
		}
	}

#ifdef CAPTURE_PTHREAD_EXIT
	if (unlikely(!org_pthread_exit_h))
		org_pthread_exit_h = (org_pthread_exit)dlsym(RTLD_NEXT, "pthread_exit");
#endif

	if (likely(tid_names != nullptr))
		tid_names->erase(_gettid());

	(*org_pthread_exit_h)(retval);
}
#endif

int pthread_mutex_lock(pthread_mutex_t *mutex)
{
	if (unlikely(!org_pthread_mutex_lock_h))
		org_pthread_mutex_lock_h = (org_pthread_mutex_lock)dlsym(RTLD_NEXT, "pthread_mutex_lock");

	int rc = (*org_pthread_mutex_lock_h)(mutex);

	if (likely(rc == 0))
		store_mutex_info(mutex, a_lock);
	else if (rc == EDEADLK)
		store_mutex_info(mutex, a_deadlock);

	return rc;
}

int pthread_mutex_trylock(pthread_mutex_t *mutex)
{
	if (unlikely(!org_pthread_mutex_lock_h))
		org_pthread_mutex_trylock_h = (org_pthread_mutex_trylock)dlsym(RTLD_NEXT, "pthread_mutex_trylock");

	int rc = (*org_pthread_mutex_trylock_h)(mutex);

	if (likely(rc == 0))
		store_mutex_info(mutex, a_lock);
	else if (rc == EDEADLK)
		store_mutex_info(mutex, a_deadlock);

	return rc;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
	if (unlikely(!org_pthread_mutex_unlock_h))
		org_pthread_mutex_unlock_h = (org_pthread_mutex_unlock)dlsym(RTLD_NEXT, "pthread_mutex_unlock");

	int rc = (*org_pthread_mutex_unlock_h)(mutex);

	if (likely(rc == 0))
		store_mutex_info(mutex, a_unlock);
	else if (rc == EDEADLK)
		store_mutex_info(mutex, a_deadlock);

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
	fprintf(stderr, "Lock tracer starting... (structure size: %zu bytes)\n", sizeof(lock_trace_item_t));

	items = new lock_trace_item_t[16777216];

	tid_names = new std::map<int, std::string>();

	// FIXME intercept:
	// 	int pthread_mutex_trylock(pthread_mutex_t *mutex);
	//	int pthread_rwlock_rdlock(pthread_rwlock_t *rwlock);
	//	int pthread_rwlock_tryrdlock(pthread_rwlock_t *rwlock);
	//	int pthread_rwlock_wrlock(pthread_rwlock_t *rwlock);
	//	int pthread_rwlock_unlock(pthread_rwlock_t *rwlock);
}

void exit(int status)
{
	fprintf(stderr, "Lock tracer terminating... (path: %s)\n", get_current_dir_name());

	if (!items)
		fprintf(stderr, "No items recorded yet\n");
	else {
		FILE *fh = fopen("dump.dat", "w");

		if (!fh)
			fh = stderr;

		fprintf(fh, "t\tmutex\ttid\taction\tcall chain\ttimestamp\n");

		char caller_str[512];

		if (idx > BUFFER_SIZE)
			idx = BUFFER_SIZE;

		for(uint64_t i = 0; i<idx; i++) {
			caller_str[0] = 0x00;

#ifndef WITH_TIMESTAMP
			items[i].timestamp = 0;
#endif

#ifdef WITH_BACKTRACE
			for(int j=0; j<CALLER_DEPTH; j++)
				sprintf(&caller_str[strlen(caller_str)], "%p,", items[i].caller[j]);
#endif

			const char *action_name = "?";

			if (items[i].la == a_lock)
				action_name = "lock";
			else if (items[i].la == a_unlock)
				action_name = "unlock";
			else if (items[i].la == a_thread_clean)
				action_name = "tclean";
			else if (items[i].la == a_deadlock)
				action_name = "deadlock";

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

			fprintf(fh, "%zu\t%p\t%d\t%s\t%s\t%zu\t%s\n", i, items[i].lock, items[i].tid, action_name, caller_str, items[i].timestamp, name);
		}

		if (fh != stderr)
			fclose(fh);
	}

	fflush(nullptr);

	delete [] items;
	idx = 0;

	delete tid_names;

	assert(0);
}

void __attribute__ ((destructor)) stop_lock_tracing()
{
	exit(0);
}
