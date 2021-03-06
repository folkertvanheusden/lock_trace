// (C) 2021 by folkert@vanheusden.com
// released under GPL v3.0

#define __USE_GNU
#define _GNU_SOURCE
#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

#define TIME 10000000

pthread_mutex_t test = PTHREAD_MUTEX_INITIALIZER;

uint64_t get_us()
{
        struct timespec tp = { 0, 0 };

        if (clock_gettime(CLOCK_MONOTONIC, &tp) == -1) {
                perror("clock_gettime");
                return 0;
	}

        return tp.tv_sec * 1000l * 1000l + tp.tv_nsec / 1000;
}

void lock_unlock(pthread_mutex_t *const mutex)
{
	uint64_t start = get_us();

	do {
		pthread_mutex_lock(mutex);

		pthread_yield();
		usleep((random() % 1500) + 5);

		pthread_mutex_unlock(mutex);

		pthread_yield();
		usleep((random() % 1500) + 5);
	} while (get_us() - start <= TIME);
}

void *thread(void *p)
{
	pthread_mutex_t *mutex = (pthread_mutex_t *)p;

	pthread_setname_np(pthread_self(), "test-cont");

	lock_unlock(mutex);

	return NULL;
}

void test_mutex()
{
	pthread_mutex_t mutex, mutex2, mutex3 = PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP, mutex4 = PTHREAD_MUTEX_INITIALIZER;
	pthread_mutexattr_t attr, attr2;

	pthread_setname_np(pthread_self(), "test-mutex");

	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&mutex, &attr);
	pthread_mutexattr_destroy(&attr);

	pthread_mutexattr_init(&attr2);
	pthread_mutexattr_settype(&attr2, PTHREAD_MUTEX_ERRORCHECK);
	pthread_mutex_init(&mutex2, &attr2);
	pthread_mutexattr_destroy(&attr2);

	/* try to simulate contention */
	pthread_t th;
	pthread_create(&th, NULL, thread, &mutex);

	lock_unlock(&mutex);

	pthread_mutex_lock(&test); /* test lock */
	pthread_mutex_unlock(&test); /* test double unlock */
	pthread_mutex_unlock(&test); /* test double unlock */

	pthread_mutex_lock(&mutex); /* test double lock */

	/* test performance of lock + unlock */
	uint64_t cnt = 0;
	uint64_t start = get_us();

	do {
		pthread_mutex_lock(&mutex4);

		cnt++;

		pthread_mutex_unlock(&mutex4);
		pthread_mutex_unlock(&mutex4);
		pthread_mutex_unlock(&mutex4);
		pthread_mutex_unlock(&mutex4);
	} while (get_us() - start <= TIME);

	printf("%f/s\n", cnt / (TIME / 1000000.0));

	pthread_mutex_lock(&mutex); /* test double lock */
	pthread_mutex_lock(&mutex);

	pthread_mutex_trylock(&mutex); /* test trylock */

	pthread_mutex_unlock(&mutex); /* test invalid unlock */
	pthread_mutex_unlock(&mutex);
	pthread_mutex_unlock(&mutex);
	pthread_mutex_unlock(&mutex);

	pthread_mutex_lock(&mutex); /* test "still locked" */

	pthread_mutex_lock(&mutex2); /* test deadlock */
	pthread_mutex_lock(&mutex2);

	uint64_t dummy = 0;
	for(int i=0; i<1024; i++) { /* test adaptive lock */
		pthread_mutex_lock(&mutex3);
		dummy += i * cnt;
		pthread_mutex_unlock(&mutex3);
	}
}

void test_rwlock()
{
	pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;

	pthread_setname_np(pthread_self(), "test-rwlock");

	pthread_rwlock_rdlock(&rwlock);  // regular
	pthread_rwlock_unlock(&rwlock);

	pthread_rwlock_wrlock(&rwlock);  // regular
	pthread_rwlock_unlock(&rwlock);

	pthread_rwlock_wrlock(&rwlock);  // double write-lock
	pthread_rwlock_wrlock(&rwlock);

	pthread_rwlock_unlock(&rwlock);  // regular
	pthread_rwlock_unlock(&rwlock);  // double un-lock
	pthread_rwlock_unlock(&rwlock);

	pthread_rwlock_rdlock(&rwlock);
	pthread_rwlock_rdlock(&rwlock);  // double read-lock

	pthread_rwlock_unlock(&rwlock);
	pthread_rwlock_unlock(&rwlock);  // double un-lock
	pthread_rwlock_unlock(&rwlock);
}

void test_try_lock()
{
	pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;

	pthread_setname_np(pthread_self(), "test-try-lock");

	pthread_rwlock_rdlock(&rwlock);

	pthread_rwlock_tryrdlock(&rwlock);
	pthread_rwlock_trywrlock(&rwlock);

	struct timespec ts = { 0, 0 };

	pthread_rwlock_timedrdlock(&rwlock, &ts);
	pthread_rwlock_timedwrlock(&rwlock, &ts);
}

void * signal_c_func(void *arg)
{
	pthread_cond_t *cond = (pthread_cond_t *)arg;
	usleep(501000);
	pthread_cond_signal(cond);

	return NULL;
}

void test_conditional()
{
	pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

	pthread_setname_np(pthread_self(), "test-conditional");

	pthread_t signal_c;
	pthread_create(&signal_c, NULL, signal_c_func, &cond);

	pthread_mutex_lock(&mutex);
	pthread_cond_wait(&cond, &mutex);
	pthread_mutex_unlock(&mutex);

	pthread_join(signal_c, NULL);
}

int main(int argc, char *argv[])
{
	test_mutex();

	test_rwlock();

	test_try_lock();

	test_conditional();

	pthread_setname_np(pthread_self(), "main");

	exit(0);  // trigger dump in trace library
}
