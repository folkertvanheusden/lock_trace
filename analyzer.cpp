#include <error.h>
#include <fcntl.h>
#include <jansson.h>
#include <map>
#include <set>
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

	lock_trace_item_t *items = (lock_trace_item_t *)mmap(nullptr, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (items == MAP_FAILED) {
		fprintf(stderr, "mmap failed: %s\n", strerror(errno));
		return nullptr;
	}

	if (posix_madvise(items, st.st_size, POSIX_MADV_SEQUENTIAL) == -1)
		perror("posix_madvise");

	close(fd);

	return items;
}

// mae_already_locked: already locked by this tid
// mae_not_locked: unlock without lock
// mae_not_owner: other thread unlocks mutex
typedef enum { mae_already_locked, mae_not_locked, mae_not_owner } mutex_action_error_t;

std::vector<std::pair<uint64_t, mutex_action_error_t> > find_double_un_locks(const lock_trace_item_t *const items, const size_t n_records)
{
	std::vector<std::pair<uint64_t, mutex_action_error_t> > out;

	std::map<const pthread_mutex_t *, std::set<pid_t> > locked;

	for(size_t i=0; i<n_records; i++) {
		const pthread_mutex_t *const lock = (const pthread_mutex_t *)items[i].lock;
		const pid_t tid = items[i].tid;

		if (items[i].la == a_lock) {
			// see if it is already locked by current 'tid' which is a mistake
			auto it = locked.find(lock);
			if (it != locked.end()) {
				if (it->second.find(tid) != it->second.end())
					out.push_back({ i, mae_already_locked });
			}
		}
		else if (items[i].la == a_unlock) {
			// see if it is not locked (mistake)
			auto it = locked.find(lock);
			if (it != locked.end())
				out.push_back({ i, mae_not_locked });
			// see if it is not locked by current tid (mistake)
			else {
				auto tid_it = it->second.find(tid);
				if (tid_it == it->second.end())
					out.push_back({ i, mae_not_owner });
			}
		}
	}

	return out;
}

int main(int argc, char *argv[])
{
	std::string trace_file, core_file, resolver, output_file;

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

	// TODO emit meta

	auto mutex_lock_failures = find_double_un_locks(data, n_records);
	printf("%zu\n", mutex_lock_failures.size());


	fclose(fh);
}
