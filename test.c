// (C) 2021 by folkert@vanheusden.com
// released under GPL v3.0

#define __USE_GNU
#define _GNU_SOURCE
#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>

#define TIME 2000000

uint64_t get_us()
{
        struct timeval tv = { 0, 0 };
        gettimeofday(&tv, NULL);

        return tv.tv_sec * 1000l * 1000l + tv.tv_usec;
}

int main(int argc, char *argv[])
{
	pthread_mutex_t mutex, mutex2;
	pthread_mutexattr_t attr, attr2;

	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&mutex, &attr);
	pthread_mutexattr_destroy(&attr);

	pthread_mutexattr_init(&attr2);
	pthread_mutexattr_settype(&attr2, PTHREAD_MUTEX_ERRORCHECK);
	pthread_mutex_init(&mutex2, &attr2);
	pthread_mutexattr_destroy(&attr2);

	pthread_setname_np(pthread_self(), "test-main");

	pthread_mutex_lock(&mutex); /* test double lock */

	/* test performance of lock + unlock */
	uint64_t cnt = 0;
	uint64_t start = get_us();

	do {
		pthread_mutex_lock(&mutex);

		cnt++;

		pthread_mutex_unlock(&mutex);
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

	exit(0);  // trigger dump in trace library
}
