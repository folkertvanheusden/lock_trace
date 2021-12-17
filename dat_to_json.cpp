#include <fcntl.h>
#include <jansson.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "config.h"
#include "lock_tracer.h"

void write_json_int(FILE *const fh, const char *const key, const uint64_t v, const bool more)
{
    fprintf(fh, "\"%s\":%lu%s", key, v, more ? "," : "");
}

void write_json_string(FILE *const fh, const char *const key, const char *const v, const bool more)
{
    size_t n = strlen(v);

    char *out = (char *)malloc(n * 2 + 1);
    size_t o = 0;

    for(size_t i=0; i<n; i++) {
        if (v[i] == '\n') {
            out[o++] = '\\';
            out[o++] = 'n';
        }
        else if (v[i] == '"') {
            out[o++] = '\\';
            out[o++] = '"';
        }
        else if (v[i] == '\\') {
            out[o++] = '\\';
            out[o++] = '\\';
        }
        else {
            out[o++] = v[i];
        }
    }

    out[o] = 0x00;

    fprintf(fh, "\"%s\":\"%s\"%s", key, out, more ? "," : "");

    free(out);
}

int main(int argc, char *argv[])
{
    json_error_t err;
    json_t *meta = json_load_file(argv[1], 0, &err);

    char *data_filename = nullptr;
    uint64_t n_rec = 0;

    size_t meta_n = json_array_size(meta);
    printf("# meta data records: %zu\n", meta_n);

    for(size_t i=0; i<meta_n; i++) {
        json_t *cur = json_array_get(meta, i);

        json_t *v1 = json_object_get(cur, "measurements");
        if (v1)
            data_filename = strdup(json_string_value(v1));

        json_t *v2 = json_object_get(cur, "n_records");
        if (v2)
            n_rec = json_integer_value(v2);
    }

    json_decref(meta);

    printf("%lu records in %s\n", n_rec, data_filename);

    int fd = open(data_filename, O_RDONLY);

    struct stat st;
    fstat(fd, &st);

    lock_trace_item_t *items = (lock_trace_item_t *)mmap(nullptr, st.st_size, PROT_READ, MAP_SHARED, fd, 0);

    posix_madvise(items, st.st_size, POSIX_MADV_SEQUENTIAL);

    close(fd);

    char *dot = strrchr(data_filename, '.');
    if (dot)
        *dot = 0x00;

    char *json_filename = nullptr;
    asprintf(&json_filename, "%s.json", data_filename);

    FILE *fh = fopen(json_filename, "wb");

    fprintf(fh, "[");

    char caller_str[512];

    for(uint64_t i = 0; i<n_rec; i++) {
        fprintf(fh, "{");

        caller_str[0] = 0x00;

#ifdef WITH_BACKTRACE
	int d = CALLER_DEPTH - 1;
	while(d >= 0 && !items[i].caller[d])
		d--;

        for(int j=0; j<=d; j++)
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
        else if (items[i].la == a_error)
            action_name = "error";
        else if (items[i].la == a_r_lock)
            action_name = "readlock", rw_lock = true;
        else if (items[i].la == a_w_lock)
            action_name = "writelock", rw_lock = true;
        else if (items[i].la == a_rw_unlock)
            action_name = "rwunlock", rw_lock = true;
        else if (items[i].la == a_init)
            action_name = "init";
        else if (items[i].la == a_destroy)
            action_name = "destroy";
        else if (items[i].la == a_rw_init)
            action_name = "rw_init";
        else if (items[i].la == a_rw_destroy)
            action_name = "rw_destroy";

        if (items[i].thread_name[0])
            write_json_string(fh, "thread_name", items[i].thread_name, true);
        else
            write_json_string(fh, "thread_name", "?", true);

        write_json_int(fh, "t", i, true);
        write_json_int(fh, "lock", (unsigned long long int)items[i].lock, true);
        write_json_int(fh, "tid", items[i].tid, true);
        write_json_string(fh, "action", action_name, true);
        write_json_string(fh, "caller", caller_str, true);
#ifdef MEASURE_TIMING
        write_json_int(fh, "timestamp", items[i].timestamp, true);
        write_json_int(fh, "lock_took", items[i].lock_took, true);
#else
        write_json_int(fh, "timestamp", 0, true);
        write_json_int(fh, "lock_took", 0, true);
#endif
        write_json_int(fh, "rc", items[i].rc, true);

        if (rw_lock) {
            write_json_int(fh, "rwlock_readers", items[i].rwlock_innards.__readers, true);
            write_json_int(fh, "rwlock_writers", items[i].rwlock_innards.__writers, true);
            write_json_int(fh, "cur_writer",     items[i].rwlock_innards.__cur_writer, false);
        }
        else {
            write_json_int(fh, "mutex_count", items[i].mutex_innards.__count, true);
            write_json_int(fh, "mutex_owner", items[i].mutex_innards.__owner, true);
            write_json_int(fh, "mutex_kind",  items[i].mutex_innards.__kind, true);
#ifdef __x86_64__
            write_json_int(fh, "mutex_spins",  items[i].mutex_innards.__spins, true);
            write_json_int(fh, "mutex_elision",  items[i].mutex_innards.__elision, false);
#endif
        }

        if (i < n_rec - 1)
            fprintf(fh, "},");
        else
            fprintf(fh, "}");
    }

    fprintf(fh, "]");

    fclose(fh);

    printf("Output written to %s\n", json_filename);

    return 0;
}
