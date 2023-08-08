// (C) 2021-2023 by folkert@vanheusden.com
// released under Apache license v2.0

#include "config.h"

#include <algorithm>
#include <assert.h>
#include <cfloat>
#include <error.h>
#include <fcntl.h>
#if HAVE_GVC == 1
#include <gvc.h>
#endif
#include <jansson.h>
#include <map>
#include <math.h>
#include <optional>
#include <set>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <string.h>
#include <time.h>
#include <vector>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "lock_tracer.h"

std::string resolver = "/usr/bin/eu-addr2line";
std::string core_file, exe_file;

std::string myformat(const char *const fmt, ...)
{
	char *buffer = nullptr;
	va_list ap;

	va_start(ap, fmt);
	if (vasprintf(&buffer, fmt, ap) == -1) {
		va_end(ap);
		return "(?)";
	}
	va_end(ap);

	std::string result = buffer;
	free(buffer);

	return result;
}

json_t *load_json(const std::string & filename)
{
	json_error_t error { 0 };
	json_t *rc = json_load_file(filename.c_str(), 0, &error);

	if (!rc) {
		fprintf(stderr, "Meta data file (dump.dat) broken: %s\n", error.text);
		return nullptr;
	}

	return rc;
}

std::string lock_action_to_name(const lock_action_t la)
{
	if (la == a_lock)
		return "lock";
	else if (la == a_unlock)
		return "unlock";
	else if (la == a_thread_clean)
		return "thread_clean";
	else if (la == a_r_lock)
		return "r_lock";
	else if (la == a_w_lock)
		return "w_lock";
	else if (la == a_rw_unlock)
		return "rw_unlock";
	else if (la == a_init)
		return "init";
	else if (la == a_destroy)
		return "destroy";
	else if (la == a_rw_init)
		return "rw_init";
	else if (la == a_rw_destroy)
		return "rw_destroy";

	return "internal error";
}

const lock_trace_item_t *load_data(const std::string & filename)
{
	int fd = open(filename.c_str(), O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "Failed opening %s: %s\n", filename.c_str(), strerror(errno));
		return nullptr;
	}

	struct stat st;
	fstat(fd, &st);

	lock_trace_item_t *data = (lock_trace_item_t *)mmap(nullptr, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (data == MAP_FAILED) {
		fprintf(stderr, "mmap failed: %s\n", strerror(errno));
		return nullptr;
	}

	if (posix_madvise(data, st.st_size, POSIX_MADV_SEQUENTIAL) == -1)
		perror("posix_madvise");

	close(fd);

	return data;
}

const lock_usage_groups_t *load_ug_data(const std::string & filename)
{
	int fd = open(filename.c_str(), O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "Failed opening %s: %s\n", filename.c_str(), strerror(errno));
		return nullptr;
	}

	struct stat st;
	fstat(fd, &st);

	lock_usage_groups_t *data = (lock_usage_groups_t *)mmap(nullptr, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (data == MAP_FAILED) {
		fprintf(stderr, "mmap failed: %s\n", strerror(errno));
		return nullptr;
	}

	if (posix_madvise(data, st.st_size, POSIX_MADV_SEQUENTIAL) == -1)
		perror("posix_madvise");

	close(fd);

	return data;
}

typedef uint64_t hash_t;

uint64_t MurmurHash64A(const void *const key, const int len, const uint64_t seed)
{
	const uint64_t m = 0xc6a4a7935bd1e995LLU;
	const int r = 47;

	uint64_t h = seed ^ (len * m);

	const uint64_t *data = (const uint64_t *)key;
	const uint64_t *end = (len >> 3) + data;

	while(data != end) {
		uint64_t k = *data++;

		k *= m;
		k ^= k >> r;
		k *= m;

		h ^= k;
		h *= m;
	}

	const uint8_t *data2 = (const uint8_t *)data;

	switch(len & 7) {
		case 7: h ^= (uint64_t)(data2[6]) << 48;
		case 6: h ^= (uint64_t)(data2[5]) << 40;
		case 5: h ^= (uint64_t)(data2[4]) << 32;
		case 4: h ^= (uint64_t)(data2[3]) << 24;
		case 3: h ^= (uint64_t)(data2[2]) << 16;
		case 2: h ^= (uint64_t)(data2[1]) << 8;
		case 1: h ^= (uint64_t)(data2[0]);
			h *= m;
	};

	h ^= h >> r;
	h *= m;
	h ^= h >> r;

	return h;
}

hash_t calculate_backtrace_hash(const void *const *const pointers, const size_t n_pointers)
{
	// hash the contents of the pointer-array instead of where they point to
	return MurmurHash64A((const void *const)pointers, n_pointers * sizeof(void *), 0);
}

// lae_already_locked: already locked by this tid
// lae_not_locked: unlock without lock
// lae_not_owner: other thread unlocks mutex
typedef enum { lae_already_locked = 0, lae_not_locked, lae_not_owner } lock_action_error_t;
constexpr const char *const lock_action_error_str[] = { "already locked", "not locked", "not owner (or not waiting for (r/w-lock))" };

typedef struct {
	std::vector<size_t> latest_records;
	size_t first_record;
} double_un_lock_t;

template<typename Type>
void put_lock_error(std::map<std::pair<const Type *, lock_action_error_t>, std::map<hash_t, double_un_lock_t> > *const target, const Type *const lock, const lock_action_error_t error_type, const hash_t calltrace_hash, const size_t record_nr)
{
	std::pair<const Type *, lock_action_error_t> key { lock, error_type };
	auto it = target->find(key);

	if (it == target->end()) {
		// this kind of error we've not seen earlier with this lock
		std::map<hash_t, double_un_lock_t> entry;

		double_un_lock_t data;
		data.first_record = record_nr;
		entry.insert({ calltrace_hash, data });

		target->insert({ key, entry });
	}
	else {
		// this error occured earlier with this lock
		auto hash_map_it = it->second.find(calltrace_hash);

		if (hash_map_it == it->second.end()) {
			double_un_lock_t data;
			data.first_record = record_nr;

			it->second.insert({ calltrace_hash, data });
		}
		else {
			hash_map_it->second.latest_records.push_back(record_nr);
		}
	}
}

// this may give false positives if for example an other mutex is malloced()/new'd
// over the location of a previously unlocked mutex
typedef struct {
	std::set<pid_t> tids;
} lock_record_t;

auto do_find_double_un_locks_mutex(const lock_trace_item_t *const data, const size_t n_records)
{
	std::map<std::pair<const pthread_mutex_t *, lock_action_error_t>, std::map<hash_t, double_un_lock_t> > out;

	std::map<const pthread_mutex_t *, lock_record_t> locked;

	for(size_t i=0; i<n_records; i++) {
		const pthread_mutex_t *const mutex = (const pthread_mutex_t *)data[i].lock;
		const pid_t tid = data[i].tid;

		// ignore calls that failed
		if (data[i].rc != 0)
			continue;

		if (data[i].la == a_lock) {
			// see if it is already locked by current 'tid' which is a mistake
			auto it = locked.find(mutex);
			if (it != locked.end()) {
				if (it->second.tids.find(tid) != it->second.tids.end()) {
					hash_t hash = calculate_backtrace_hash(data[i].caller, CALLER_DEPTH);

					put_lock_error(&out, mutex, lae_already_locked, hash, i);
				}
				else {
					// new locker of this mutex
					it->second.tids.insert(tid);
				}
			}
			else {
				// new mutex
				locked.insert({ mutex, { { tid } } });
			}
		}
		else if (data[i].la == a_unlock) {
			// see if it is not locked (mistake)
			auto it = locked.find(mutex);
			if (it == locked.end()) {
				hash_t hash = calculate_backtrace_hash(data[i].caller, CALLER_DEPTH);

				put_lock_error(&out, mutex, lae_not_locked, hash, i);
			}
			// see if it is not locked by current tid (mistake)
			else {
				auto tid_it = it->second.tids.find(tid);
				if (tid_it == it->second.tids.end()) {
					hash_t hash = calculate_backtrace_hash(data[i].caller, CALLER_DEPTH);

					put_lock_error(&out, mutex, lae_not_owner, hash, i);
				}
				else {
					it->second.tids.erase(tid_it);
				}

				if (it->second.tids.empty())
					locked.erase(it);
			}
		}
	}

	return out;
}

std::map<const void *, std::string> symbol_cache;

std::string lookup_symbol(const void *const p)
{
	if (p == nullptr)
		return "(nil)";

	auto it = symbol_cache.find(p);
	if (it != symbol_cache.end())
		return it->second;

	std::string command_line;

	if (core_file.empty() == false)
		command_line = myformat("%s -x -a -C --core %s %p", resolver.c_str(), core_file.c_str(), p);
	else
		command_line = myformat("%s -x -a -C -e %s %p", resolver.c_str(), exe_file.c_str(), p);

	char buffer[4096] { 0x00 };

	FILE *fh = popen(command_line.c_str(), "r");
	if (fh) {
		if (fread(buffer, 1, sizeof buffer - 1, fh) == 0)
			buffer[0] = 0x00;

		for(;;) {
			char *lf = strchr(buffer, '\n');
			if (!lf)
				break;

			*lf = '/';
		}

		pclose(fh);
	}
	else {
		fprintf(stderr, "Cannot resolve symbol (\"%s\"): %s\n", command_line.c_str(), strerror(errno));
	}

	char *lf = strchr(buffer, '\n');
	if (lf)
		*lf = 0x00;

	std::string result = buffer;

	if (result.substr(0, 2) == "??" || result == "")
		result = myformat("%p", p);

	symbol_cache.insert({ p, result });

	return result;
}

#if defined(WITH_BACKTRACE)
void put_call_trace_html(FILE *const fh, const lock_trace_item_t & record, const std::string & table_color)
{
	fprintf(fh, "<table class=\"%s\">\n", table_color.c_str());

	int d = CALLER_DEPTH - 1;
	while(d > 0 && record.caller[d] == nullptr)
		d--;

	for(int i=0; i<=d; i++)
		fprintf(fh, "<tr><th>%p</th><td>%s</td></tr>\n", record.caller[i], lookup_symbol(record.caller[i]).c_str());

	fprintf(fh, "</table>\n");
}
void put_call_trace_text(FILE *const fh, const lock_trace_item_t & record)
{
	int d = CALLER_DEPTH - 1;
	while(d > 0 && record.caller[d] == nullptr)
		d--;

	if (d >= 0) {
		fprintf(fh, "\t");

		for(int i=0; i<=d; i++)
			fprintf(fh, "%p ", record.caller[i]);

		fprintf(fh, "%s", lookup_symbol(record.caller[d]).c_str());
	}
}
#endif

constexpr uint64_t billion = 1000000000ll;

std::string my_ctime(const uint64_t nts)
{
	time_t t = nts / billion;

	struct tm tm { 0 };
	localtime_r(&t, &tm);

	return myformat("%04d-%02d-%02d %02d:%02d:%02d.%09d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, int(nts % billion));
}

void put_record_details_html(FILE *const fh, const lock_trace_item_t & record, const std::string & base_color)
{
	fprintf(fh, "<table class=\"%s\">\n", base_color.c_str());
	fprintf(fh, "<tr><th>tid</th><td>%d</td></tr>\n", record.tid);
#ifdef STORE_THREAD_NAME
	fprintf(fh, "<tr><th>thread name</th><td>%s</td></tr>\n", record.thread_name);
#endif
#ifdef MEASURE_TIMING
	fprintf(fh, "<tr><th>action</th><td>%s</td></tr>\n", lock_action_to_name(record.la).c_str());
	fprintf(fh, "<tr><th>lock</th><td>%p</td></tr>\n", record.lock);
	fprintf(fh, "<tr><th>timestamp</th><td>%s</td></tr>\n", my_ctime(record.timestamp).c_str());
	fprintf(fh, "<tr><th>took</th><td>%.3fus</td></tr>\n", record.lock_took / 1000.0);
#endif

#if defined(WITH_BACKTRACE)
	fprintf(fh, "<tr><th>call trace</th><td>");
	put_call_trace_html(fh, record, base_color);
	fprintf(fh, "</td></tr>\n");
#endif

	fprintf(fh, "</table>\n");
}

void put_record_details_text(FILE *const fh, const lock_trace_item_t & record)
{
	fprintf(fh, "%d", record.tid);
#ifdef STORE_THREAD_NAME
	if (record.thread_name[0])
		fprintf(fh, "\t%s", record.thread_name);
	else
		fprintf(fh, "\t-");
#endif
#ifdef MEASURE_TIMING
	fprintf(fh, "\t%s", lock_action_to_name(record.la).c_str());
	fprintf(fh, "\t%p", record.lock);
	fprintf(fh, "\t%s", my_ctime(record.timestamp).c_str());
	fprintf(fh, "\t%.3fus", record.lock_took / 1000.);
#endif

#if defined(WITH_BACKTRACE)
	put_call_trace_text(fh, record);
#endif

	fprintf(fh, "\n");
}

std::map<hash_t, size_t> find_a_record_for_unique_backtrace_hashes(const lock_trace_item_t *const data, const std::vector<size_t> & backtraces)
{
	std::map<hash_t, size_t> out;

	for(auto i : backtraces) {
		hash_t hash = calculate_backtrace_hash(data[i].caller, CALLER_DEPTH);

		auto it = out.find(hash);
		if (it == out.end())
			out.insert({ hash, i });
	}

	return out;
}

void find_double_un_locks_mutex(FILE *const fh, const lock_trace_item_t *const data, const uint64_t n_records)
{
	auto mutex_lock_mistakes = do_find_double_un_locks_mutex(data, n_records);

	fprintf(fh, "<section>\n");
	fprintf(fh, "<h2 id=\"doublem\">4. mutex lock/unlock mistakes</h2>\n");
	fprintf(fh, "<p>Mistakes are: locking a mutex another time by the same thread, unlocking mutexes that are not locked and unlocking of a mutex by some other thread than the one who locked the mutex.</p>\n");
	fprintf(fh, "<p>This section contains a list of all the seen mutex/error-type combinations and then for each the mistakes made and then one or more backtraces (\"first\" and \"next\") where they occured.</p>\n");
	fprintf(fh, "<p>Count: %zu</p>\n", mutex_lock_mistakes.size());

	for(auto mutex_lock_mistake : mutex_lock_mistakes) {
		fprintf(fh, "<h3>mutex %p, type \"%s\"</h3>\n", (const void *)mutex_lock_mistake.first.first, lock_action_error_str[mutex_lock_mistake.first.second]);

		for(auto map_entry : mutex_lock_mistake.second) {
			double_un_lock_t & dul = map_entry.second;

			// first (correct?)
			if (dul.latest_records.empty() == false)
				fprintf(fh, "<h4>first</h4>\n");
			put_record_details_html(fh, data[dul.first_record], "red");

			// then list all mistakes for this combination, show only unique backtraces
			if (dul.latest_records.empty() == false) {
				fprintf(fh, "<h4>next</h4>\n");
				fprintf(fh, "<p>Mistake count: %zu (total number of backtraces seen; note that the list below is de-duplicated).</p>\n", dul.latest_records.size());

				auto unique_backtraces = find_a_record_for_unique_backtrace_hashes(data, dul.latest_records);

				for(auto entry : unique_backtraces) 
					put_record_details_html(fh, data[entry.second], "red");
			}

			fprintf(fh, "<br>\n");
		}
	}

	fprintf(fh, "</section>\n");
}

std::map<int, std::vector<size_t> > do_list_fuction_call_errors(const lock_trace_item_t *const data, const uint64_t n_records)
{
	std::map<int, std::vector<size_t> > errors;

	for(size_t i=0; i<n_records; i++) {
		if (data[i].rc == 0)
			continue;

		auto it = errors.find(data[i].rc);
		if (it == errors.end())
			errors.insert({ data[i].rc, { i } });
		else
			it->second.push_back(i);
	}

	return errors;
}

void list_fuction_call_errors(FILE *const fh, const lock_trace_item_t *const data, const uint64_t n_records)
{
	auto error_list = do_list_fuction_call_errors(data, n_records);

	fprintf(fh, "<section>\n");
	fprintf(fh, "<h2 id=\"errors\">3. function call errors</h2>\n");
	fprintf(fh, "<p>pthread_-functions can fail, they then return an errno-alike error code. In this section, all that occured (for the ones checked, like mutex errors etc) are listed.</p>\n");
	fprintf(fh, "<p>Count: %zu</p>\n", error_list.size());

	for(auto it : error_list) {
		fprintf(fh, "<h3>%s</h3>\n", strerror(it.first));

		auto unique_backtraces = find_a_record_for_unique_backtrace_hashes(data, it.second);

		for(auto entry : unique_backtraces)  {
			put_record_details_html(fh, data[entry.second], "green");

			fprintf(fh, "<br>\n");
		}
	}

	fprintf(fh, "</section>\n");
}

std::map<const pthread_mutex_t *, std::vector<size_t> > do_find_still_locked_mutex(const lock_trace_item_t *const data, const uint64_t n_records)
{
	std::map<const pthread_mutex_t *, int> mutexes_counts;

	std::map<const pthread_mutex_t *, std::vector<size_t> > mutexes_where;

	for(size_t i=0; i<n_records; i++) {
		// ignore calls that failed
		if (data[i].rc != 0)
			continue;

		const pthread_mutex_t *const mutex = (const pthread_mutex_t *)data[i].lock;

		if (data[i].la == a_lock) {
			auto it = mutexes_counts.find(mutex);

			if (it == mutexes_counts.end()) {
				mutexes_counts.insert({ mutex, 1 });
				mutexes_where.insert({ mutex, { i } });
			}
			else {
				it->second++;
				mutexes_where.find(mutex)->second.push_back(i);
			}
		}
		else if (data[i].la == a_unlock) {
			auto it = mutexes_counts.find(mutex);

			if (it != mutexes_counts.end()) {
				if (it->second > 0)
					it->second--;

				if (it->second == 0) {
					mutexes_counts.erase(mutex);
					mutexes_where.erase(mutex);
				}
			}
		}
	}

	return mutexes_where;
}

void find_still_locked_mutex(FILE *const fh, const lock_trace_item_t *const data, const uint64_t n_records)
{
	auto still_locked_list = do_find_still_locked_mutex(data, n_records);

	fprintf(fh, "<section>\n");
	fprintf(fh, "<h2 id=\"stillm\">5. still locked mutexes</h2>\n");
	fprintf(fh, "<p>A list of the mutexes that were still locked when the program terminated.</p>\n");
	fprintf(fh, "<p>Count: %zu</p>\n", still_locked_list.size());

	for(auto it : still_locked_list) {
		fprintf(fh, "<h3>mutex %p</h3>\n", (const void *)it.first);

		auto unique_backtraces = find_a_record_for_unique_backtrace_hashes(data, it.second);

		if (unique_backtraces.size() == 1)
			fprintf(fh, "<p>The following location did not unlock:</p>\n");
		else
			fprintf(fh, "<p>One of the following locations did not unlock:</p>\n");

		for(auto entry : unique_backtraces) {
			put_record_details_html(fh, data[entry.second], "blue");

			fprintf(fh, "<br>\n");
		}
	}

	fprintf(fh, "</section>\n");
}

std::map<const pthread_rwlock_t *, std::vector<size_t> > do_find_still_locked_rwlock(const lock_trace_item_t *const data, const uint64_t n_records)
{
	std::map<const pthread_rwlock_t *, int> rwlocks_counts;

	std::map<const pthread_rwlock_t *, std::vector<size_t> > rwlockes_where;

	for(size_t i=0; i<n_records; i++) {
		// ignore calls that failed
		if (data[i].rc != 0)
			continue;

		const pthread_rwlock_t *const rwlock = (const pthread_rwlock_t *)data[i].lock;

		if (data[i].la == a_r_lock || data[i].la == a_w_lock) {
			auto it = rwlocks_counts.find(rwlock);

			if (it == rwlocks_counts.end()) {
				rwlocks_counts.insert({ rwlock, 1 });
				rwlockes_where.insert({ rwlock, { i } });
			}
			else {
				it->second++;
				rwlockes_where.find(rwlock)->second.push_back(i);
			}
		}
		else if (data[i].la == a_rw_unlock) {
			// here it is not important if it is the r or
			// the w lock, as long as the count matches up
			auto it = rwlocks_counts.find(rwlock);

			if (it != rwlocks_counts.end()) {
				if (it->second > 0)
					it->second--;

				if (it->second == 0) {
					rwlocks_counts.erase(rwlock);
					rwlockes_where.erase(rwlock);
				}
			}
		}
	}

	return rwlockes_where;
}

void find_still_locked_rwlock(FILE *const fh, const lock_trace_item_t *const data, const uint64_t n_records)
{
	auto still_locked_list = do_find_still_locked_rwlock(data, n_records);

	fprintf(fh, "<section>\n");
	fprintf(fh, "<h2 id=\"stillrw\">7. still locked rwlocks</h2>\n");
	fprintf(fh, "<p>A list of the r/w-locks that were still locked when the program terminated.</p>\n");
	fprintf(fh, "<p>Count: %zu</p>\n", still_locked_list.size());

	for(auto it : still_locked_list) {
		fprintf(fh, "<h3>rwlock %p</h3>\n", (const void *)it.first);

		auto unique_backtraces = find_a_record_for_unique_backtrace_hashes(data, it.second);

		if (unique_backtraces.size() == 1)
			fprintf(fh, "<p>The following location did not unlock:</p>\n");
		else
			fprintf(fh, "<p>One of the following locations did not unlock:</p>\n");

		for(auto entry : unique_backtraces) {
			put_record_details_html(fh, data[entry.second], "magenta");

			fprintf(fh, "<br>\n");
		}
	}

	fprintf(fh, "</section>\n");
}

// see do_find_double_un_locks_mutex comment about false positives
auto do_find_double_un_locks_rwlock(const lock_trace_item_t *const data, const size_t n_records)
{
	std::map<std::pair<const pthread_rwlock_t *, lock_action_error_t>, std::map<hash_t, double_un_lock_t> > out;

	std::map<const pthread_rwlock_t *, std::set<pid_t> > r_locked;
	std::map<const pthread_rwlock_t *, std::set<pid_t> > w_locked;

	for(size_t i=0; i<n_records; i++) {
		// ignore calls that failed
		if (data[i].rc != 0)
			continue;

		const pthread_rwlock_t *const rwlock = (const pthread_rwlock_t *)data[i].lock;
		const pid_t tid = data[i].tid;

		if (data[i].la == a_r_lock) {
			// see if it is already locked by current 'tid' which is a mistake
			auto it = r_locked.find(rwlock);
			if (it != r_locked.end()) {
				if (it->second.find(tid) != it->second.end()) {
					hash_t hash = calculate_backtrace_hash(data[i].caller, CALLER_DEPTH);

					put_lock_error(&out, rwlock, lae_already_locked, hash, i);
				}
				else {
					// new locker of this rwlock
					it->second.insert(tid);
				}
			}
			else {
				// new rwlock
				r_locked.insert({ rwlock, { tid } });
			}
		}
		else if (data[i].la == a_w_lock) {
			auto it = w_locked.find(rwlock);
			if (it != w_locked.end()) {
				if (it->second.find(tid) != it->second.end()) {
					hash_t hash = calculate_backtrace_hash(data[i].caller, CALLER_DEPTH);

					put_lock_error(&out, rwlock, lae_already_locked, hash, i);
				}
				else {
					it->second.insert(tid);
				}
			}
			else {
				w_locked.insert({ rwlock, { tid } });
			}
		}
		else if (data[i].la == a_rw_unlock) {
			// see if it is not locked (mistake)
			auto w_it = w_locked.find(rwlock);
			if (w_it == w_locked.end()) {
				// check r_locked

				auto r_it = r_locked.find(rwlock);
				if (r_it == r_locked.end()) {
					hash_t hash = calculate_backtrace_hash(data[i].caller, CALLER_DEPTH);

					put_lock_error(&out, rwlock, lae_not_locked, hash, i);
				}
				// see if it is not locked by current tid (mistake)
				else {
					auto tid_it = r_it->second.find(tid);
					if (tid_it == r_it->second.end()) {
						hash_t hash = calculate_backtrace_hash(data[i].caller, CALLER_DEPTH);

						put_lock_error(&out, rwlock, lae_not_owner, hash, i);
					}
					else {
						r_it->second.erase(tid_it);
					}

					if (r_it->second.empty())
						r_locked.erase(r_it);
				}
			}
			// see if it is not locked by current tid (mistake)
			// that is: not locked or waiting to acquire the w-lock
			else {
				auto tid_it = w_it->second.find(tid);
				if (tid_it == w_it->second.end()) {
					hash_t hash = calculate_backtrace_hash(data[i].caller, CALLER_DEPTH);

					put_lock_error(&out, rwlock, lae_not_owner, hash, i);
				}
				else {
					w_it->second.erase(tid_it);
				}

				if (w_it->second.empty())
					w_locked.erase(w_it);
			}
		}
	}

	return out;
}

void find_double_un_locks_rwlock(FILE *const fh, const lock_trace_item_t *const data, const uint64_t n_records)
{
	auto rw_lock_mistakes = do_find_double_un_locks_rwlock(data, n_records);

	fprintf(fh, "<section>\n");
	fprintf(fh, "<h2 id=\"doublerw\">6. r/w-lock lock/unlock mistakes</h2>\n");
	fprintf(fh, "<p>Mistakes are: read-locking a r/w-lock another time by the same thread, unlocking r/w-locks that are not locked and unlocking of an r/w-lock by some other thread than the one who locked it.</p>\n");
	fprintf(fh, "<p>This section contains a list of all the seen r/w-lock/error-type combinations and then for each the mistakes made and then one or more backtraces (\"first\" and \"next\") where they occured.</p>\n");
	fprintf(fh, "<p>Count: %zu</p>\n", rw_lock_mistakes.size());

	// go through all mutexes for which a mistake was made
	for(auto rwlock_lock_mistake : rw_lock_mistakes) {
		fprintf(fh, "<h3>r/w-lock %p, type \"%s\"</h3>\n", (const void *)rwlock_lock_mistake.first.first, lock_action_error_str[rwlock_lock_mistake.first.second]);

		// go through every combination (lock + unlocks)
		for(auto map_entry : rwlock_lock_mistake.second) {
			double_un_lock_t & dul = map_entry.second;

			// first (correct?)
			if (dul.latest_records.empty() == false)
				fprintf(fh, "<h4>first</h4>\n");

			put_record_details_html(fh, data[dul.first_record], "yellow");

			// then list all mistakes for this combination, show only unique backtraces
			if (dul.latest_records.empty() == false) {
				fprintf(fh, "<h4>next</h4>\n");
				fprintf(fh, "<p>Mistake count: %zu (total number of backtraces seen; note that the list below is de-duplicated).</p>\n", dul.latest_records.size());

				auto unique_backtraces = find_a_record_for_unique_backtrace_hashes(data, dul.latest_records);

				for(auto entry : unique_backtraces) 
					put_record_details_html(fh, data[entry.second], "yellow");
			}

			fprintf(fh, "<br>\n");
		}
	}

	fprintf(fh, "</section>\n");
}

void put_html_header(FILE *const fh, const bool run_correlate)
{
	fprintf(fh, "<!DOCTYPE html>\n<html lang=\"en\"><head>\n");
	fprintf(fh, "<meta charset=\"utf-8\">\n");
	fprintf(fh, "<style>.svgbox{height:768px;width:1024px;overflow:scroll}thead th{ background: #ffb0b0}table{font-size:16px;border-collapse:collapse;border-spacing:0;}td,th{border:1px solid #ddd;text-align:left;padding:8px}tr:nth-child(even){background-color:#f2f2f2}.green{background-color:#c0ffc0}.red{background-color:#ffc0c0}.blue{background-color:#c0c0ff}.yellow{background-color:#ffffa0}.magenta{background-color:#ffa0ff}th{padding-top:11px;padding-bottom:11px;background-color:#04aa6d;color:#fff}h1,h2,h3{margin-top:2.2em;}</style>\n");
	fprintf(fh, "<title>lock trace</title></head><body>\n");
	fprintf(fh, "<h1>LOCK TRACE</h1>\n");

	fprintf(fh, "<h2>table of contents</h2>\n");
	fprintf(fh, "<p>Please note: the colors are only used for easier reading, they don't have a special meaning.</p>\n");
	fprintf(fh, "<ol>\n");
	fprintf(fh, "<li><a href=\"#meta\">meta data</a>\n");
	fprintf(fh, "<li><a href=\"#durations\">durations</a>\n");
	fprintf(fh, "<li><a class=\"green\" href=\"#errors\">errors</a>\n");
	fprintf(fh, "<li><a class=\"red\" href=\"#doublem\">double lock/unlock mutexes</a>\n");
	fprintf(fh, "<li><a class=\"blue\" href=\"#stillm\">still locked mutexes</a>\n");
	fprintf(fh, "<li><a class=\"yellow\" href=\"#doublerw\">double lock/unlock r/w-locks</a>\n");
	fprintf(fh, "<li><a class=\"magenta\" href=\"#stillrw\">still locked r/w-locks</a>\n");
	fprintf(fh, "<li><a class=\"green\" href=\"#whereused\">where are locks used</a>\n");
	if (run_correlate)
		fprintf(fh, "<li><a href=\"#corr\">correlations between locks</a>\n");
	fprintf(fh, "</ol>\n");

	fprintf(fh, "<p>The \"tid\" is the thread identifier of the thread that triggered a measurement.</p>\n");
}

void put_html_tail(FILE *const fh)
{
	const char footer[] = "<p><br><br></p><hr><footer>This <b>locktracer</b> is (C) 2021 by Folkert van Heusden &lt;mail@vanheusden.com&gt;</footer></body></html>\n";

	if (fprintf(fh, "<p><br><br></p><hr><footer>This <b>locktracer</b> is (C) 2021 by Folkert van Heusden &lt;mail@vanheusden.com&gt;</footer></body></html>\n") != sizeof footer - 1)
		fprintf(stderr, "Problem writing output-file: filesystem full?\n");
}

std::string get_json_string(const json_t *const js, const char *const key)
{
	return json_string_value(json_object_get(js, key));
}

int64_t get_json_int(const json_t *const js, const char *const key)
{
	return json_integer_value(json_object_get(js, key));
}

std::map<std::string, uint64_t> data_stats(const lock_trace_item_t *const data, const uint64_t n_records)
{
	uint64_t cnts[_a_max][2] { { 0, 0 } };

	for(uint64_t i=0; i<n_records; i++)
		cnts[data[i].la][!!data[i].rc]++;

	std::map<std::string, uint64_t> out;
	out.insert({ "mutex locks", cnts[a_lock][0] });
	out.insert({ "mutex unlocks", cnts[a_unlock][0] });
	out.insert({ "pthread_clean", cnts[a_thread_clean][0] });
	out.insert({ "rw read lock", cnts[a_r_lock][0] });
	out.insert({ "rw write lock", cnts[a_w_lock][0] });
	out.insert({ "rw unlock", cnts[a_rw_unlock][0] });
	out.insert({ "mutex init", cnts[a_init][0] });
	out.insert({ "mutex destroy", cnts[a_destroy][0] });
	out.insert({ "rw init", cnts[a_rw_init][0] });
	out.insert({ "rw destroy", cnts[a_rw_destroy][0] });

	out.insert({ "failed mutex locks", cnts[a_lock][1] });
	out.insert({ "failed mutex unlocks", cnts[a_unlock][1] });
	out.insert({ "failed pthread_clean", cnts[a_thread_clean][1] });
	out.insert({ "failed rw read lock", cnts[a_r_lock][1] });
	out.insert({ "failed rw write lock", cnts[a_w_lock][1] });
	out.insert({ "failed rw unlock", cnts[a_rw_unlock][1] });
	out.insert({ "failed mutex init", cnts[a_init][1] });
	out.insert({ "failed mutex destroy", cnts[a_destroy][1] });
	out.insert({ "failed rw init", cnts[a_rw_init][1] });
	out.insert({ "failed rw destroy", cnts[a_rw_destroy][1] });

	return out;
}

void emit_meta_data(FILE *const fh, const json_t *const meta, const std::string & core_file_in, const std::string & trace_file, const lock_trace_item_t *const data, const uint64_t n_records)
{
	fprintf(fh, "<h2 id=\"meta\">1. META DATA</h2>\n");
	fprintf(fh, "<table><tr><th colspan=2>meta data</th></tr>\n");
	fprintf(fh, "<tr><th>executable</th><td>%s</td></tr>\n", get_json_string(meta, "exe_name").c_str());
	fprintf(fh, "<tr><th>PID</th><td>%ld</td></tr>\n", get_json_int(meta, "pid"));
	fprintf(fh, "<tr><th>scheduler</th><td>%s</td></tr>\n", get_json_string(meta, "scheduler").c_str());
	fprintf(fh, "<tr><th>host name</th><td>%s</td></tr>\n", get_json_string(meta, "hostname").c_str());
	fprintf(fh, "<tr><th>core file</th><td>%s</td></tr>\n", core_file_in.c_str());
	fprintf(fh, "<tr><th>trace file</th><td>%s</td></tr>\n", trace_file.c_str());
	double took = double(get_json_int(meta, "end_ts") - get_json_int(meta, "start_ts")) / billion;
	uint64_t _n_records = get_json_int(meta, "n_records");
	uint64_t _n_records_max = get_json_int(meta, "n_records_max");
	double n_per_sec = took > 0 ? _n_records / took: 0;
	fprintf(fh, "<tr><th># trace records</th><td>%lu (%.2f%%, %.2f%%/s)</td></tr>\n", _n_records, _n_records * 100.0 / _n_records_max, n_per_sec * 100.0 / _n_records_max);
	fprintf(fh, "<tr><th>fork warning</th><td>%s</td></tr>\n", get_json_int(meta, "fork_warning") ? "true" : "false");
	fprintf(fh, "<tr><th># cores</th><td>%ld</td></tr>\n", get_json_int(meta, "n_procs"));
	uint64_t start_ts = get_json_int(meta, "start_ts");
	uint64_t end_ts = get_json_int(meta, "end_ts");
	fprintf(fh, "<tr><th>started at</th><td>%.9f (%s)</td></tr>\n", start_ts / double(billion), my_ctime(start_ts).c_str());
	fprintf(fh, "<tr><th>stopped at</th><td>%.9f (%s)</td></tr>\n", end_ts / double(billion), my_ctime(end_ts).c_str());
	fprintf(fh, "<tr><th>took</th><td>%fs</td></tr>\n", took);
	fprintf(fh, "</table>\n");

	fprintf(fh, "<h3>counts</h3>\n");
	fprintf(fh, "<table>\n");
	fprintf(fh, "<tr><th># mutex try-locks</th><td>%ld</td></tr>\n", get_json_int(meta, "cnt_mutex_trylock"));
	fprintf(fh, "<tr><th># rwlock try-rdlock</th><td>%ld</td></tr>\n", get_json_int(meta, "cnt_rwlock_try_rdlock"));
	fprintf(fh, "<tr><th># rwlock try-timed-rdlock</th><td>%ld</td></tr>\n", get_json_int(meta, "cnt_rwlock_try_timedrdlock"));
	fprintf(fh, "<tr><th># rwlock try-wrlock</th><td>%ld</td></tr>\n", get_json_int(meta, "cnt_rwlock_try_wrlock"));
	fprintf(fh, "<tr><th># rwlock try-timed-rwlock</th><td>%ld</td></tr>\n", get_json_int(meta, "cnt_rwlock_try_timedwrlock"));

	assert(n_records == _n_records);
	auto ds = data_stats(data, n_records);
	for(auto ds_entry : ds)
		fprintf(fh, "<tr><th>%s</th><td>%lu</td></tr>\n", ds_entry.first.c_str(), ds_entry.second);

	fprintf(fh, "</table>\n");
}

typedef struct {
	uint64_t mutex_lock_acquire_durations, n_mutex_acquire_locks, mutex_lock_acquire_sd, mutex_lock_acquire_max;
} durations_mutex_t;

typedef struct {
	uint64_t mutex_locked_durations, n_mutex_locked_durations, mutex_locked_durations_sd, mutex_locked_durations_max;
} locked_durations_mutex_t;

typedef struct {
	uint64_t rwlock_r_lock_acquire_durations, n_rwlock_r_acquire_locks, rwlock_r_lock_acquire_sd, rwlock_r_lock_acquire_max;
} durations_rwlock_r_t;

typedef struct {
	uint64_t rwlock_w_lock_acquire_durations, n_rwlock_w_acquire_locks, rwlock_w_lock_acquire_sd, rwlock_w_lock_acquire_max;
} durations_rwlock_w_t;

typedef struct {
	uint64_t rwlock_r_locked_durations, n_rwlock_r_locked, rwlock_r_locked_sd, rwlock_r_locked_max;
	uint64_t rwlock_w_locked_durations, n_rwlock_w_locked, rwlock_w_locked_sd, rwlock_w_locked_max;
} locked_durations_rwlock_t;

typedef struct {
	// acquire
	durations_mutex_t durations_mutex;
	std::map<pthread_mutex_t *, durations_mutex_t> per_mutex_durations;
	// hold
	locked_durations_mutex_t locked_durations;
	std::map<pthread_mutex_t *, locked_durations_mutex_t> per_mutex_locked_durations;

	// acquire
	durations_rwlock_r_t durations_r_rwlock;
	durations_rwlock_w_t durations_w_rwlock;
	std::map<pthread_rwlock_t *, durations_rwlock_r_t> per_rwlock_r_acquire_durations;
	std::map<pthread_rwlock_t *, durations_rwlock_w_t> per_rwlock_w_acquire_durations;
	// hold
	std::map<pthread_rwlock_t *, locked_durations_rwlock_t> per_rwlock_locked_durations;
} durations_t;

typedef struct {
	uint64_t w_timestamp;
	int __cur_writer;  // tid of who holds the write lock

	uint64_t r_timestamp;
} rwlock_holder_t;

durations_t do_determine_durations(const lock_trace_item_t *const data, const uint64_t n_records)
{
	durations_t d;
	d.durations_mutex = { 0 };
	d.locked_durations = { 0 };
	d.durations_r_rwlock = { 0 };
	d.durations_w_rwlock = { 0 };

	std::map<pthread_mutex_t *, uint64_t> mutex_acquire_timestamp;

	std::map<pthread_rwlock_t *, rwlock_holder_t> rwlock_acquire_timestamp;

	for(uint64_t i=0; i<n_records; i++) {
		if (data[i].rc != 0)  // ignore failed calls
			continue;

		const uint64_t took = data[i].lock_took;

		if (data[i].la == a_lock) {
			d.durations_mutex.mutex_lock_acquire_durations += took;
			d.durations_mutex.mutex_lock_acquire_sd += took * took;
			d.durations_mutex.mutex_lock_acquire_max = std::max(d.durations_mutex.mutex_lock_acquire_max, took);
			d.durations_mutex.n_mutex_acquire_locks++;

			pthread_mutex_t *mutex_lock = (pthread_mutex_t *)data[i].lock;

			mutex_acquire_timestamp.insert({ mutex_lock, data[i].timestamp });

			auto it = d.per_mutex_durations.find(mutex_lock);
			if (it == d.per_mutex_durations.end())
				d.per_mutex_durations.insert({ mutex_lock, { took, 1, took * took, took } });
			else {
				it->second.mutex_lock_acquire_durations += took;
				it->second.n_mutex_acquire_locks++;
				it->second.mutex_lock_acquire_sd += took * took;
				it->second.mutex_lock_acquire_max = std::max(it->second.mutex_lock_acquire_max, took);
			}
		}
		else if (data[i].la == a_unlock) {
			auto lock_it = mutex_acquire_timestamp.find((pthread_mutex_t *)data[i].lock);

			if (lock_it != mutex_acquire_timestamp.end()) {
				uint64_t t_delta_took = data[i].timestamp - lock_it->second;

				mutex_acquire_timestamp.erase(lock_it);

				d.locked_durations.mutex_locked_durations += t_delta_took;
				d.locked_durations.n_mutex_locked_durations++;
				d.locked_durations.mutex_locked_durations_sd += t_delta_took * t_delta_took;
				d.locked_durations.mutex_locked_durations_sd = std::max(d.locked_durations.mutex_locked_durations_max, t_delta_took);

				pthread_mutex_t *mutex_lock = (pthread_mutex_t *)data[i].lock;

				auto it = d.per_mutex_locked_durations.find(mutex_lock);
				if (it == d.per_mutex_locked_durations.end())
					d.per_mutex_locked_durations.insert({ mutex_lock, { t_delta_took, 1, t_delta_took * t_delta_took, t_delta_took } });
				else {
					it->second.mutex_locked_durations += t_delta_took;
					it->second.n_mutex_locked_durations++;
					it->second.mutex_locked_durations_sd += t_delta_took * t_delta_took;
					it->second.mutex_locked_durations_sd = std::max(it->second.mutex_locked_durations_max, t_delta_took);
				}
			}
		}
		else if (data[i].la == a_r_lock) {
			pthread_rwlock_t *rwlock_lock = (pthread_rwlock_t *)data[i].lock;

			// acquiring
			d.durations_r_rwlock.rwlock_r_lock_acquire_durations += took;
			d.durations_r_rwlock.n_rwlock_r_acquire_locks++;
			d.durations_r_rwlock.rwlock_r_lock_acquire_sd += took * took;
			d.durations_r_rwlock.rwlock_r_lock_acquire_max = std::max(d.durations_r_rwlock.rwlock_r_lock_acquire_max, took);
			// per lock 'r_took'
			auto ar_it = d.per_rwlock_r_acquire_durations.find(rwlock_lock);
			if (ar_it == d.per_rwlock_r_acquire_durations.end())
				d.per_rwlock_r_acquire_durations.insert({ rwlock_lock, { took, 1, took * took, took } });
			else {
				ar_it->second.rwlock_r_lock_acquire_durations += took;
				ar_it->second.n_rwlock_r_acquire_locks++;
				ar_it->second.rwlock_r_lock_acquire_sd += took * took;
				ar_it->second.rwlock_r_lock_acquire_max = std::max(ar_it->second.rwlock_r_lock_acquire_max, took);
			}

			// locked durations
			auto d_it = rwlock_acquire_timestamp.find(rwlock_lock);
			if (d_it == rwlock_acquire_timestamp.end())
				rwlock_acquire_timestamp.insert({ rwlock_lock, { 0, 0, data[i].timestamp } });
			else
				d_it->second.r_timestamp = data[i].timestamp;
		}
		else if (data[i].la == a_w_lock) {
			pthread_rwlock_t *rwlock_lock = (pthread_rwlock_t *)data[i].lock;

			// acquiring
			d.durations_w_rwlock.rwlock_w_lock_acquire_durations += took;
			d.durations_w_rwlock.rwlock_w_lock_acquire_sd += took * took;
			d.durations_w_rwlock.rwlock_w_lock_acquire_max = std::max(d.durations_w_rwlock.rwlock_w_lock_acquire_max, took);
			d.durations_w_rwlock.n_rwlock_w_acquire_locks++;
			// per lock 'w_took'
			auto aw_it = d.per_rwlock_w_acquire_durations.find(rwlock_lock);
			if (aw_it == d.per_rwlock_w_acquire_durations.end())
				d.per_rwlock_w_acquire_durations.insert({ rwlock_lock, { took, 1, took * took, took } });
			else {
				aw_it->second.rwlock_w_lock_acquire_durations += took;
				aw_it->second.n_rwlock_w_acquire_locks++;
				aw_it->second.rwlock_w_lock_acquire_sd += took * took;
				aw_it->second.rwlock_w_lock_acquire_max = std::max(aw_it->second.rwlock_w_lock_acquire_max, took);
			}

			// locked durations
			auto it = rwlock_acquire_timestamp.find(rwlock_lock);
			if (it == rwlock_acquire_timestamp.end())
				rwlock_acquire_timestamp.insert({ rwlock_lock, { data[i].timestamp, data[i].tid, 0 } });
			else {
				it->second.w_timestamp = data[i].timestamp;
				it->second.__cur_writer = data[i].tid;
			}
		}
		else if (data[i].la == a_rw_unlock) {
			pthread_rwlock_t *rwlock_lock = (pthread_rwlock_t *)data[i].lock;

			auto lock_it = rwlock_acquire_timestamp.find(rwlock_lock);

			if (lock_it != rwlock_acquire_timestamp.end()) {
				if (lock_it->second.__cur_writer == data[i].tid && lock_it->second.w_timestamp > 0) {  // write lock
					uint64_t t_delta_took = data[i].timestamp - lock_it->second.w_timestamp;

					lock_it->second.w_timestamp = 0;

					auto it = d.per_rwlock_locked_durations.find(rwlock_lock);

					if (it != d.per_rwlock_locked_durations.end()) {
						it->second.rwlock_w_locked_durations += t_delta_took;
						it->second.n_rwlock_w_locked++;
						it->second.rwlock_w_locked_sd += t_delta_took * t_delta_took;
						it->second.rwlock_w_locked_max = std::max(it->second.rwlock_w_locked_max, t_delta_took);
					}
					else {
						d.per_rwlock_locked_durations.insert({ rwlock_lock, { 0, 0, 0, t_delta_took, 1, t_delta_took * t_delta_took, t_delta_took } });
					}
				}
				else if (lock_it->second.r_timestamp > 0) {  // read lock
					uint64_t t_delta_took = data[i].timestamp - lock_it->second.r_timestamp;

					lock_it->second.r_timestamp = 0;

					auto it = d.per_rwlock_locked_durations.find(rwlock_lock);

					if (it != d.per_rwlock_locked_durations.end()) {
						it->second.rwlock_r_locked_durations += t_delta_took;
						it->second.n_rwlock_r_locked++;
						it->second.rwlock_r_locked_sd += t_delta_took * t_delta_took;
						it->second.rwlock_r_locked_max = std::max(it->second.rwlock_r_locked_max, t_delta_took);
					}
					else {
						d.per_rwlock_locked_durations.insert({ rwlock_lock, { t_delta_took, 1, t_delta_took * t_delta_took, 0, 0, 0, t_delta_took } });
					}
				}
			}
		}
	}

	return d;
}

void determine_durations(FILE *const fh, const lock_trace_item_t *const data, const uint64_t n_records)
{
	const auto & d = do_determine_durations(data, n_records);

	fprintf(fh, "<section>\n");

	fprintf(fh, "<h2 id=\"durations\">2. acquisition durations</h2>\n");
	fprintf(fh, "<p>How long it took before a mutex (or r/w-lock) was acquired. This takes longer if an other thread is already holding it and doesn't immediately return it.</p>\n");
	fprintf(fh, "<p>Also shown is, how long mutex was held on average. 'sd' is the standard deviation.</p>\n");
	fprintf(fh, "<table>\n");

	// mutex acquisition durations
	double avg_mutex_lock_acquire_durations = d.durations_mutex.mutex_lock_acquire_durations / double(d.durations_mutex.n_mutex_acquire_locks);
	double sd_mutex_lock_acquire_durations = sqrt(d.durations_mutex.mutex_lock_acquire_sd / double(d.durations_mutex.n_mutex_acquire_locks) - pow(avg_mutex_lock_acquire_durations, 2.0));
	fprintf(fh, "<tr><th>mutex</th><td>avg: %.3fus, sd: %.3fus, max: %.3fus</td></tr>\n", avg_mutex_lock_acquire_durations / 1000.0, sd_mutex_lock_acquire_durations / 1000.0, d.durations_mutex.mutex_lock_acquire_max / 1000.);

	// mutex held durations
	double avg_mutex_locked_durations = d.locked_durations.mutex_locked_durations / double(d.locked_durations.n_mutex_locked_durations);
	if (d.locked_durations.n_mutex_locked_durations > 1) {
		double sd_mutex_locked_durations = sqrt(d.locked_durations.mutex_locked_durations_sd / double(d.locked_durations.n_mutex_locked_durations) - pow(avg_mutex_locked_durations, 2.0));
		fprintf(fh, "<tr><th>mutex held</th><td>avg: %.3fus, sd: %.3fus, max: %.3fus</td></tr>\n", avg_mutex_locked_durations / 1000.0, sd_mutex_locked_durations / 1000.0, d.locked_durations.mutex_locked_durations_max / 1000.);
	}
	else {
		fprintf(fh, "<tr><th>mutex held</th><td>avg: %.3fus, max: %.3fus</td></tr>\n", avg_mutex_locked_durations / 1000.0, d.locked_durations.mutex_locked_durations_max / 1000.);
	}

	// read lock of r/w locks
	double avg_rwlock_r_lock_acquire_durations = d.durations_r_rwlock.rwlock_r_lock_acquire_durations / double(d.durations_r_rwlock.n_rwlock_r_acquire_locks);
	double sd_rwlock_r_lock_acquire_durations = sqrt(d.durations_r_rwlock.rwlock_r_lock_acquire_sd / double(d.durations_r_rwlock.n_rwlock_r_acquire_locks) - pow(avg_rwlock_r_lock_acquire_durations, 2.0));
	fprintf(fh, "<tr><th>read lock</th><td>avg: %.3fus, sd: %.3fus, max: %.3fus</td></tr>\n", avg_rwlock_r_lock_acquire_durations / 1000.0, sd_rwlock_r_lock_acquire_durations / 1000.0, d.durations_r_rwlock.rwlock_r_lock_acquire_max / 1000.);

	// write lock of r/w locks
	double avg_rwlock_w_lock_acquire_durations = d.durations_w_rwlock.rwlock_w_lock_acquire_durations / double(d.durations_w_rwlock.n_rwlock_w_acquire_locks);
	double sd_rwlock_w_lock_acquire_durations = sqrt(d.durations_w_rwlock.rwlock_w_lock_acquire_sd / double(d.durations_w_rwlock.n_rwlock_w_acquire_locks) - pow(avg_rwlock_w_lock_acquire_durations, 2.0));
	fprintf(fh, "<tr><th>write lock</th><td>avg: %.3fus, sd: %.3fus, max: %.3fus</td></tr>\n", avg_rwlock_w_lock_acquire_durations / 1000.0, sd_rwlock_w_lock_acquire_durations, d.durations_w_rwlock.rwlock_w_lock_acquire_max / 1000.);

	fprintf(fh, "</table>\n");

	fprintf(fh, "<h3>per mutex durations</h3>\n");

	fprintf(fh, "<h4>acquiration duration</h4>\n");
	fprintf(fh, "<table>\n");
	fprintf(fh, "<tr><th>pointer</th><th>average</th><th>standard deviation</th><th>maximum</th></tr>\n");
	for(auto entry : d.per_mutex_durations) {
		double avg = entry.second.mutex_lock_acquire_durations / double(entry.second.n_mutex_acquire_locks);
		double sd = sqrt(entry.second.mutex_lock_acquire_sd / double(entry.second.n_mutex_acquire_locks) - pow(avg, 2.0));

		fprintf(fh, "<tr><th>%s</th><td>%.3fus</td><td>%.3fus</td><td>%.3fus</td></tr>\n", lookup_symbol(entry.first).c_str(), avg, sd, entry.second.mutex_lock_acquire_max * 1.);
	}
	fprintf(fh, "</table>\n");

	fprintf(fh, "<h4>mutex held duration</h4>\n");
	fprintf(fh, "<table>\n");
	fprintf(fh, "<tr><th>pointer</th><th>average</th><th>standard deviation</th><th>maximum</th></tr>\n");
	for(auto entry : d.per_mutex_locked_durations) {
		double avg = entry.second.mutex_locked_durations / double(entry.second.n_mutex_locked_durations);
		double sd = sqrt(entry.second.mutex_locked_durations_sd / double(entry.second.n_mutex_locked_durations) - pow(avg, 2.0));

		fprintf(fh, "<tr><th>%s</th><td>%.3fus</td><td>%.3fus</td><td>%.3fus</td></tr>\n", lookup_symbol(entry.first).c_str(), avg, sd, entry.second.mutex_locked_durations_max * 1.);
	}
	fprintf(fh, "</table>\n");

	fprintf(fh, "<h3>per r/w lock durations</h3>\n");

	fprintf(fh, "<h4>read lock acquiration duration</h4>\n");
	fprintf(fh, "<table>\n");
	fprintf(fh, "<tr><th>pointer</th><th>r/w</th><th>average</th><th>standard deviation</th><th>maximum</th></tr>\n");
	for(auto entry : d.per_rwlock_r_acquire_durations) {
		double avg = entry.second.rwlock_r_lock_acquire_durations / double(entry.second.n_rwlock_r_acquire_locks);
		double sd = sqrt(entry.second.rwlock_r_lock_acquire_sd / double(entry.second.n_rwlock_r_acquire_locks) - pow(avg, 2.0));

		fprintf(fh, "<tr><th>%s</th><td>%.3fus</td><td>%.3fus</td><td>%.3fus</td></tr>\n", lookup_symbol(entry.first).c_str(), avg, sd, entry.second.rwlock_r_lock_acquire_max * 1.);
	}
	fprintf(fh, "</table>\n");

	fprintf(fh, "<h4>write lock acquiration duration</h4>\n");
	fprintf(fh, "<table>\n");
	fprintf(fh, "<tr><th>pointer</th><th>r/w</th><th>average</th><th>standard deviation</th><th>maximum</th></tr>\n");
	for(auto entry : d.per_rwlock_w_acquire_durations) {
		double avg = entry.second.rwlock_w_lock_acquire_durations / double(entry.second.n_rwlock_w_acquire_locks);
		double sd = sqrt(entry.second.rwlock_w_lock_acquire_sd / double(entry.second.n_rwlock_w_acquire_locks) - pow(avg, 2.0));

		fprintf(fh, "<tr><th>%s</th><td>%.3fus</td><td>%.3fus</td><td>%.3fus</td></tr>\n", lookup_symbol(entry.first).c_str(), avg, sd, entry.second.rwlock_w_lock_acquire_max * 1.);
	}
	fprintf(fh, "</table>\n");

	fprintf(fh, "<h4>r/w-lock held duration</h4>\n");
	fprintf(fh, "<table>\n");
	fprintf(fh, "<tr><th>pointer</th><th>r/w></th><th>average</th><th>standard deviation</th><th>maximum</th></tr>\n");
	for(auto entry : d.per_rwlock_locked_durations) {
		double r_avg = entry.second.rwlock_r_locked_durations / double(entry.second.n_rwlock_r_locked);
		double r_sd = sqrt(entry.second.rwlock_r_locked_sd / double(entry.second.n_rwlock_r_locked) - pow(r_avg, 2.0));

		double w_avg = entry.second.rwlock_w_locked_durations / double(entry.second.n_rwlock_w_locked);
		double w_sd = sqrt(entry.second.rwlock_w_locked_sd / double(entry.second.n_rwlock_w_locked) - pow(r_avg, 2.0));

		fprintf(fh, "<tr><th>%s</th><td>r</td><td>%.3fus</td><td>%.3fus</td><td>%.3fus</td></tr>\n", lookup_symbol(entry.first).c_str(), r_avg, r_sd, entry.second.rwlock_r_locked_max * 1.);
		fprintf(fh, "<tr><th></th><td>w</td><td>%.3fus</td><td>%.3fus</td></tr>\n", w_avg, w_sd);
	}
	fprintf(fh, "</table>\n");

	fprintf(fh, "</section>\n");
}

// lock, backtrace
std::map<const void *, std::map<hash_t, uint64_t> > do_where_are_locks_used(const lock_trace_item_t *const data, const uint64_t n_records)
{
	std::map<const void *, std::map<hash_t, uint64_t> > out;

	for(uint64_t i=0; i<n_records; i++) {
		if (data[i].rc != 0)  // ignore failed calls
			continue;

		if (data[i].la == a_lock || data[i].la == a_r_lock || data[i].la == a_w_lock) {
			hash_t h = calculate_backtrace_hash(data[i].caller, CALLER_DEPTH);

			auto lock_it = out.find(data[i].lock);
			if (lock_it != out.end())
				lock_it->second.insert({ h, i });
			else {
				std::map<hash_t, uint64_t> d;
				d.insert({ h, i });

				out.insert({ data[i].lock, d });
			}
		}
	}

	return out;
}

void where_are_locks_used(FILE *const fh, const lock_trace_item_t *const data, const uint64_t n_records)
{
	auto lock_use_locations = do_where_are_locks_used(data, n_records);

	fprintf(fh, "<section>\n");

	fprintf(fh, "<h2 id=\"whereused\">8. where are locks used</h2>\n");
	fprintf(fh, "<table class=\"green\">\n");
	for(auto & entry : lock_use_locations) {
		fprintf(fh, "<tr><td>%s</td><td>\n", lookup_symbol(entry.first).c_str());

		for(const auto & p : entry.second) {
			put_call_trace_html(fh, data[p.second], "green");

			fprintf(fh, "<br>\n");
		}

		fprintf(fh, "</td></tr>\n");
	}
	fprintf(fh, "</table>\n");

	fprintf(fh, "</section>\n");
}

#if HAVE_GVC == 1
std::pair<std::vector<std::pair<std::pair<const void *, const void *>, uint64_t> >, std::map<const void *, uint64_t> > do_correlate(const lock_trace_item_t *const data, const uint64_t n_records)
{
	// how often is mutex/rwlock A locked while B is also locked
	std::map<std::pair<const void *, const void *>, uint64_t> counts;

	// how many instances are waiting for this lock (including the
	// one holding it)
	std::map<const void *, int> locked;

	std::map<const void *, uint64_t> seen_count;

	for(size_t i=0; i<n_records; i++) {
		// ignore calls that failed
		if (data[i].rc != 0)
			continue;

		bool do_count = false;

		if (data[i].la == a_r_lock || data[i].la == a_w_lock || data[i].la == a_lock) {
			auto it = locked.find(data[i].lock);

			if (it == locked.end())
				locked.insert({ data[i].lock, 1 });
			else
				it->second++;

			auto it_seen = seen_count.find(data[i].lock);
			if (it_seen == seen_count.end())
				seen_count.insert({ data[i].lock, 1 });
			else
				it_seen->second++;

			do_count = true;
		}
		else if (data[i].la == a_rw_unlock || data[i].la == a_unlock) {
			auto it = locked.find(data[i].lock);

			if (it == locked.end())
				locked.insert({ data[i].lock, 1 });
			else if (it->second > 0)  // here we ignore any errors
				it->second--;

			do_count = true;
		}

		if (do_count) {
			std::vector<std::pair<const void *const, int> *> ps;
			// much slower: std::transform(locked.begin(), locked.end(), std::back_inserter(ps), [](std::pair<const void *const, int> &mapItem) { return &mapItem; });
			for(auto & e : locked)
				ps.push_back(&e);

			for(size_t i1=0; i1<ps.size(); i1++) {
				for(size_t i2=i1+1; i2<ps.size(); i2++) {
					const void *a = ps.at(i1)->first;
					const void *b = ps.at(i2)->first;

					if (a > b)
						std::swap(a, b);

					std::pair<const void *, const void *> key { a, b };

					auto it = counts.find(key);
					if (it == counts.end())
						counts.insert({ key, 1 });
					else
						it->second++;
				}
			}
		}
	}

	std::vector<std::pair<std::pair<const void *, const void *>, uint64_t> > v;
	for(auto map_entry : counts)
		v.push_back(map_entry);

	return { v, seen_count };
}

void render_dot(FILE *const in, FILE *const out)
{
	GVC_t * gvc = gvContext();

	Agraph_t *g = agread(in, 0);

	gvLayout(gvc, g, "dot");

	gvRender(gvc, g, "svg", out);

	gvFreeLayout(gvc, g);
	agclose(g);
	gvFreeContext(gvc);
}

void correlate(FILE *const fh, const lock_trace_item_t *const data, const uint64_t n_records)
{
	auto pair = do_correlate(data, n_records);
	auto v = pair.first;
	auto seen_count = pair.second;

	std::sort(v.begin(), v.end(), [=](const std::pair<std::pair<const void *, const void *>, uint64_t> & a, const std::pair<std::pair<const void *, const void *>, uint64_t> & b) {
	    return a.second > b.second;
	});

	std::vector<std::pair<std::pair<const void *, const void *>, double> > v2;

	double lowest = DBL_MAX, highest = DBL_MIN;

	for(auto v_entry : v) {
		uint64_t first_seen = seen_count.find(v_entry.first.first)->second;
		uint64_t second_seen = seen_count.find(v_entry.first.second)->second;
		uint64_t min_ = std::max(first_seen, second_seen);

		double closeness = double(v_entry.second) / min_;

		highest = std::max(highest, closeness);
		lowest = std::min(lowest, closeness);

		v2.push_back({ v_entry.first, closeness });
	}

	std::sort(v2.begin(), v2.end(), [=](const std::pair<std::pair<const void *, const void *>, double> & a, const std::pair<std::pair<const void *, const void *>, double> & b) {
	    return a.second > b.second;
	});

	char *dot_script = nullptr;
	size_t dot_script_len = 0;
	FILE *dot_script_fh = open_memstream(&dot_script, &dot_script_len);

	fprintf(dot_script_fh, "graph {\n");
	fprintf(dot_script_fh, "graph[layout=neato;overlap=scalexy;sep=-0.05;splines=true;]\n");
	fprintf(dot_script_fh, "node[fontname=\"Helvetica\";]\n");
	fprintf(dot_script_fh, "node[shape=box;penwidth=\"0.5\";width=0;height=0;margin=\"0.05,0.05\";]\n");
	fprintf(dot_script_fh, "edge[label=\" \";color=\"#000080\";penwidth=\"0.5\";arrowhead=\"open\";arrowsize=\"0.7\";]\n");

	int nr = 0;
	for(auto v_entry : v2) {
		double gradient = (v_entry.second - lowest) / (highest - lowest);
		uint8_t red = 255 * gradient, blue = 255 * (1.0 - gradient);

		fprintf(dot_script_fh , " \"%p\" -- \"%p\" [style=filled color=\"#%02x%02x%02x\"];\n", v_entry.first.first, v_entry.first.second, red, 0, blue);

		// arbitrary value chosen to keep the .dot-file output readable
		if (++nr > 75)
			break;
	}

	fprintf(dot_script_fh, "}\n");

	fseek(dot_script_fh, 0, SEEK_SET);

	char *svg_script = nullptr;
	size_t svg_script_len = 0;
	FILE *svg_script_fh = open_memstream(&svg_script, &svg_script_len);

	render_dot(dot_script_fh, svg_script_fh);

	fclose(dot_script_fh);
	free(dot_script);

	fprintf(fh, "<section>\n");
	fprintf(fh, "<h2 id=\"corr\">9. which locks might be correlated</h2>\n");
	fprintf(fh, "<div class=\"svgbox\">\n");
	fwrite(svg_script, 1, svg_script_len, fh);
	fprintf(fh, "</div>\n");
	fprintf(fh, "</section>\n");

	fclose(svg_script_fh);
	free(svg_script);
}
#endif

void emit_trace(FILE *const fh, const lock_trace_item_t *const data, const uint64_t n_records, const bool html)
{
	for(uint64_t i=0; i<n_records; i++) {
		if (html)
			put_record_details_html(fh, data[i], "white");
		else
			put_record_details_text(fh, data[i]);
	}
}

void emit_locks(FILE *const fh, const lock_usage_groups_t *const data, const uint64_t n_records)
{
	std::map<void *, std::multiset<std::pair<void *, uint64_t> > > locks;

	for(uint64_t i=0; i<n_records; i++) {
		std::optional<uint64_t> erase_index;

		void *caller = data[i].caller;

		if (data[i].la == a_lock || data[i].la == a_r_lock || data[i].la == a_w_lock) {
			auto it = locks.find(data[i].lock);

			if (it == locks.end())
				locks.insert({ data[i].lock, { { caller, i } } });
			else
				it->second.insert({ caller, i });
		}
		else if (data[i].la == a_unlock || data[i].la == a_rw_unlock) {
			auto it = locks.find(data[i].lock);

			if (it != locks.end()) {
				bool found = false;

				for(auto cit = it->second.begin(); cit != it->second.end(); cit++) {
					if (data[cit->second].tid == data[i].tid) {
						erase_index = cit->second;
						it->second.erase(cit);
						found = true;
						break;
					}
				}

				if (!found)
					printf("caller %p not found in list for %p\n", caller, data[i].lock);
			}
			else {
				printf("lock %p not found\n", data[i].lock);
			}
		}

		fprintf(fh, "%s\t%p\t%s", my_ctime(data[i].timestamp).c_str(), data[i].lock, lock_action_to_name(data[i].la).c_str());

		bool first = true;
		for(auto & rec: locks.find(data[i].lock)->second)
			fprintf(fh, "%c%p|%d/%s", first ? '\t' : ' ', rec.first, data[rec.second].tid, data[rec.second].thread_name), first = false;

		if (erase_index.has_value())
			fprintf(fh, "\t[%.9f|%d/%s]", (data[i].timestamp - data[erase_index.value()].timestamp) / 1000000000., data[erase_index.value()].tid, data[erase_index.value()].thread_name);

		fprintf(fh, "\n");
	}
}

void help()
{
	printf("-t file    file name of data.dump.xxx\n");
	printf("-c file    core file\n");
	printf("-r file    path to \"eu-addr2line\"\n");
	printf("-f file    html file to write to\n");
	printf("-T x       print a trace to the file instead of statistics (x = html or ascii)\n");
	printf("-Q         show which other instances are trying to lock on a lock\n");
#if HAVE_GVC == 1
	printf("-C         toggle \"correlation graph\" (very slow!)\n");
#endif
}

int main(int argc, char *argv[])
{
	std::string trace_file, output_file;
	bool run_correlate = false;
	bool print_trace = false;
	bool is_html = false;
	bool print_locking = false;

	int c = 0;
	while((c = getopt(argc, argv, "t:c:r:f:T:QhC")) != -1) {
		if (c == 't')
			trace_file = optarg;
		else if (c == 'c')
			core_file = optarg;
		else if (c == 'r')
			resolver = optarg;
		else if (c == 'f')
			output_file = optarg;
#if HAVE_GVC == 1
		else if (c == 'C')
			run_correlate = true;
#endif
		else if (c == 'T') {
			print_trace = true;

			is_html = strcasecmp(optarg, "html") == 0;
		}
		else if (c == 'Q')
			print_locking = true;
		else if (c == 'h') {
			help();
			return 0;
		}
		else {
			help();
			return 1;
		}
	}

	if (trace_file.empty()) {
		fprintf(stderr, "Please select a trace file (dump.dat.xxx)\n");
		return 1;
	}

	if (output_file.empty()) {
		fprintf(stderr, "Please select an output file (e.g. report.html)\n");
		return 1;
	}

	json_t *const meta = load_json(trace_file);
	if (!meta)
		return 1;

	exe_file = get_json_string(meta, "exe_name");

	const lock_trace_item_t *const data = load_data(get_json_string(meta, "measurements"));

	const lock_usage_groups_t *const ug_data = load_ug_data(get_json_string(meta, "ug_measurements"));

	FILE *fh = fopen(output_file.c_str(), "w");
	if (!fh) {
		fprintf(stderr, "Failed to create %s: %s\n", output_file.c_str(), strerror(errno));
		return 1;
	}

	const uint64_t n_records = get_json_int(meta, "n_records");

	const uint64_t ug_n_records = get_json_int(meta, "ug_n_records");

	if (print_locking)
		emit_locks(fh, ug_data, ug_n_records);
	else if (print_trace)
		emit_trace(fh, data, n_records, is_html);
	else {
		put_html_header(fh, run_correlate);

		emit_meta_data(fh, meta, core_file, trace_file, data, n_records);

		determine_durations(fh, data, n_records);

		list_fuction_call_errors(fh, data, n_records);

		find_double_un_locks_mutex(fh, data, n_records);

		find_still_locked_mutex(fh, data, n_records);

		find_double_un_locks_rwlock(fh, data, n_records);

		find_still_locked_rwlock(fh, data, n_records);

		where_are_locks_used(fh, data, n_records);

#if HAVE_GVC == 1
		if (run_correlate)
			correlate(fh, data, n_records);
#endif

		put_html_tail(fh);
	}

	fclose(fh);

	json_decref(meta);

	fprintf(stderr, "Finished\n");

	return 0;
}
