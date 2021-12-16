#include <stdint.h>

typedef enum { a_lock, a_unlock, a_thread_clean, a_error, a_r_lock, a_w_lock, a_rw_unlock, a_init, a_destroy, a_rw_init, a_rw_destroy } lock_action_t;

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
#ifdef __x86_64__
			short __spins;
			short __elision;
#endif
		} mutex_innards;

		struct {
			unsigned int __readers;
			unsigned int __writers;
			int __cur_writer;  // only on __x86_64__
		} rwlock_innards;
	};

	uint64_t lock_took;

	// return code of the pthread function called
	int rc;
} lock_trace_item_t;
