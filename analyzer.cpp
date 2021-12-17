#include <error.h>
#include <fcntl.h>
#include <jansson.h>
#include <map>
#include <set>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <string.h>
#include <vector>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "config.h"
#include "lock_tracer.h"

std::string resolver = "/usr/bin/eu-addr2line";
std::string core_file;

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

// mae_already_locked: already locked by this tid
// mae_not_locked: unlock without lock
// mae_not_owner: other thread unlocks mutex
typedef enum { mae_already_locked = 0, mae_not_locked, mae_not_owner } mutex_action_error_t;
constexpr const char *const mutex_action_error_str[] = { "already locked", "not locked", "not owner" };

void put_mutex_lock_error(std::map<std::pair<const pthread_mutex_t *, mutex_action_error_t>, std::vector<size_t> > *const target, const pthread_mutex_t *const mutex, const mutex_action_error_t error_type, const size_t record_nr)
{
	std::pair<const pthread_mutex_t *, mutex_action_error_t> key { mutex, error_type };
	auto it = target->find(key);

	if (it == target->end())
		target->insert({ key, { record_nr } });
	else
		it->second.push_back(record_nr);
}

// this may give false positives if for example an other mutex is malloced()/new'd
// over the location of a previously unlocked mutex
std::map<std::pair<const pthread_mutex_t *, mutex_action_error_t>, std::vector<size_t> > do_find_double_un_locks_mutex(const lock_trace_item_t *const data, const size_t n_records)
{
	std::map<std::pair<const pthread_mutex_t *, mutex_action_error_t>, std::vector<size_t> > out;

	std::map<const pthread_mutex_t *, std::set<pid_t> > locked;

	for(size_t i=0; i<n_records; i++) {
		const pthread_mutex_t *const mutex = (const pthread_mutex_t *)data[i].lock;
		const pid_t tid = data[i].tid;

		if (data[i].la == a_lock) {
			// see if it is already locked by current 'tid' which is a mistake
			auto it = locked.find(mutex);
			if (it != locked.end()) {
				if (it->second.find(tid) != it->second.end())
					put_mutex_lock_error(&out, mutex, mae_already_locked, i);
				else {
					// new locker of this mutex
					it->second.insert(tid);
				}
			}
			else {
				// new mutex
				locked.insert({ mutex, { tid } });
			}
		}
		else if (data[i].la == a_unlock) {
			// see if it is not locked (mistake)
			auto it = locked.find(mutex);
			if (it == locked.end())
				put_mutex_lock_error(&out, mutex, mae_not_locked, i);
			// see if it is not locked by current tid (mistake)
			else {
				auto tid_it = it->second.find(tid);
				if (tid_it == it->second.end())
					put_mutex_lock_error(&out, mutex, mae_not_owner, i);

				it->second.erase(tid_it);

				if (it->second.empty())
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

	std::string command_line = myformat("%s --core %s %p", resolver.c_str(), core_file.c_str(), p);

	char buffer[4096] { 0x00 };

	FILE *fh = popen(command_line.c_str(), "r");
	if (fh) {
		if (!fgets(buffer, sizeof buffer - 1, fh))
			buffer[0] = 0x00;

		pclose(fh);
	}
	else {
		fprintf(stderr, "Cannot resolve symbol (\"%s\"): %s\n", command_line.c_str(), strerror(errno));
	}

	char *lf = strchr(buffer, '\n');
	if (lf)
		*lf = 0x00;

	std::string result = buffer;

	if (result == "??:0" || result == "")
		result = myformat("%p:-1:-1", p);

	symbol_cache.insert({ p, result });

	return result;
}

#if defined(WITH_BACKTRACE)
void put_call_trace(FILE *const fh, const lock_trace_item_t & record)
{
	fprintf(fh, "<table>\n");

	for(int i=0; i<CALLER_DEPTH; i++)
		fprintf(fh, "<tr><td>%p</td><td>%s</td></tr>\n", record.caller[i], lookup_symbol(record.caller[i]).c_str());

	fprintf(fh, "</table>\n");
}
#endif

void put_mutex_details(FILE *const fh, const lock_trace_item_t & record)
{
	fprintf(fh, "<table>\n");
	fprintf(fh, "<tr><td>tid:</td><td>%d</td></tr>\n", record.tid);
	fprintf(fh, "<tr><td>thread name:</td><td>%s</td></tr>\n", record.thread_name);

#if defined(WITH_BACKTRACE)
	fprintf(fh, "<tr><td>call trace:</td><td>");
	put_call_trace(fh, record);
	fprintf(fh, "</td></tr>\n");
#endif

	fprintf(fh, "</table>\n");
}

void find_double_un_locks_mutex(FILE *const fh, const lock_trace_item_t *const data, const uint64_t n_records)
{
	auto mutex_lock_mistakes = do_find_double_un_locks_mutex(data, n_records);

	fprintf(fh, "<article>\n");
	fprintf(fh, "<heading><h2 id=\"doublem\">mutex lock/unlock mistakes</h2></heading>\n");
	fprintf(fh, "<p>Count: %zu</p>\n", mutex_lock_mistakes.size());

	for(auto mutex_lock_mistake : mutex_lock_mistakes) {
		fprintf(fh, "<heading><h3>mutex %p, type \"%s\"</h3></heading>\n", (const void *)mutex_lock_mistake.first.first, mutex_action_error_str[mutex_lock_mistake.first.second]);

		for(auto idx : mutex_lock_mistake.second)
			put_mutex_details(fh, data[idx]);
	}

	fprintf(fh, "</article>\n");
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

	fprintf(fh, "<article>\n");
	fprintf(fh, "<heading><h2 id=\"errors\">function call errors</h2></heading>\n");
	fprintf(fh, "<p>Count: %zu</p>\n", error_list.size());

	for(auto it : error_list) {
		fprintf(fh, "<heading><h3>%s</h3></heading>\n", strerror(it.first));

		for(auto idx : it.second)
			put_mutex_details(fh, data[idx]);
	}

	fprintf(fh, "</article>\n");
}

std::map<const pthread_mutex_t *, std::vector<size_t> > do_find_still_locked_mutex(const lock_trace_item_t *const data, const uint64_t n_records)
{
	std::map<const pthread_mutex_t *, int> mutexes_counts;

	std::map<const pthread_mutex_t *, std::vector<size_t> > mutexes_where;

	for(size_t i=0; i<n_records; i++) {
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

	fprintf(fh, "<article>\n");
	fprintf(fh, "<heading><h2 id=\"stillm\">still locked mutexes</h2></heading>\n");
	fprintf(fh, "<p>Count: %zu</p>\n", still_locked_list.size());

	for(auto it : still_locked_list) {
		fprintf(fh, "<heading><h3>mutex %p</h3></heading>\n", (const void *)it.first);

		if (it.second.size() == 1)
			fprintf(fh, "<p>The following location did not unlock:</p>\n");
		else
			fprintf(fh, "<p>One of the following locations did not unlock:</p>\n");

		for(auto idx : it.second)
			put_mutex_details(fh, data[idx]);
	}

	fprintf(fh, "</article>\n");
}

void put_html_header(FILE *const fh)
{
	fprintf(fh, "<!DOCTYPE html>\n<html><head>\n");
	fprintf(fh, "<style>table{font-size:16px;font-family:\"Trebuchet MS\",Arial,Helvetica,sans-serif;border-collapse:collapse;border-spacing:0;width:100%%}td,th{border:1px solid #ddd;text-align:left;padding:8px}tr:nth-child(even){background-color:#f2f2f2}th{padding-top:11px;padding-bottom:11px;background-color:#04aa6d;color:#fff}h1,h2,h3{font-family:monospace;margin-top:2.2em;}</style>\n");
	fprintf(fh, "<title>lock trace</title></head><body>\n");
	fprintf(fh, "<h1>LOCK TRACE</h1>\n");

	fprintf(fh, "<h2>table of contents</h2>\n");
	fprintf(fh, "<ul>\n");
	fprintf(fh, "<li><a href=\"#errors\">errors</a>\n");
	fprintf(fh, "<li><a href=\"#doublem\">double lock/unlock mutexes</a>\n");
	fprintf(fh, "<li><a href=\"#stillm\">still locked mutexes</a>\n");
	fprintf(fh, "</ul>\n");
}

void put_html_tail(FILE *const fh)
{
	fprintf(fh, "<p><br><br></p><hr><font size=-1>This <b>locktracer</b> is (C) 2021 by Folkert van Heusden &lt;mail@vanheusden.com&gt;</font></body></html>\n");
}

int main(int argc, char *argv[])
{
	std::string trace_file, output_file;

	int c = 0;
	while((c = getopt(argc, argv, "t:c:r:f:")) != -1) {
		if (c == 't')
			trace_file = optarg;
		else if (c == 'c')
			core_file = optarg;
		else if (c == 'r')
			resolver = optarg;
		else if (c == 'f')
			output_file = optarg;
	}

	if (trace_file.empty()) {
		fprintf(stderr, "Please select a trace file (dump.dat.xxx)\n");
		return 1;
	}

	if (output_file.empty()) {
		fprintf(stderr, "Please select an output file (e.g. report.html)\n");
		return 1;
	}

	const json_t *const meta = load_json(trace_file);
	if (!meta)
		return 1;

	const lock_trace_item_t *const data = load_data(json_string_value(json_object_get(meta, "measurements")));

	FILE *fh = fopen(output_file.c_str(), "w");
	if (!fh) {
		fprintf(stderr, "Failed to create %s: %s\n", output_file.c_str(), strerror(errno));
		return 1;
	}

	const uint64_t n_records = json_integer_value(json_object_get(meta, "n_records"));

	put_html_header(fh);

	// TODO emit meta

	list_fuction_call_errors(fh, data, n_records);

	find_double_un_locks_mutex(fh, data, n_records);

	find_still_locked_mutex(fh, data, n_records);

	put_html_tail(fh);

	fclose(fh);
}
