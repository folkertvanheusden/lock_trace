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

    json_t *arr = json_array();

    char caller_str[512];

    for(uint64_t i = 0; i<n_rec; i++) {
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

        json_t *obj = json_object();

        if (items[i].thread_name[0])
            json_object_set(obj, "thread_name", json_string(items[i].thread_name));
        else
            json_object_set(obj, "thread_name", json_string("?"));

        json_object_set(obj, "type", json_string("data"));
        json_object_set(obj, "t", json_integer(i));
        json_object_set(obj, "lock", json_integer((long long unsigned int)items[i].lock));
        json_object_set(obj, "tid", json_integer(items[i].tid));
        json_object_set(obj, "action", json_string(action_name));
        json_object_set(obj, "caller", json_string(caller_str));
        json_object_set(obj, "timestamp", json_integer(items[i].timestamp));
        json_object_set(obj, "lock_took", json_integer(items[i].lock_took));
        json_object_set(obj, "rc", json_integer(items[i].rc));

        if (rw_lock) {
            json_object_set(obj, "rwlock_readers", json_integer(items[i].rwlock_innards.__readers));
            json_object_set(obj, "rwlock_writers", json_integer(items[i].rwlock_innards.__writers));
            json_object_set(obj, "cur_writer",     json_integer(items[i].rwlock_innards.__cur_writer));
        }
        else {
            json_object_set(obj, "mutex_count", json_integer(items[i].mutex_innards.__count));
            json_object_set(obj, "mutex_owner", json_integer(items[i].mutex_innards.__owner));
            json_object_set(obj, "mutex_kind",  json_integer(items[i].mutex_innards.__kind));
#ifdef __x86_64__
            json_object_set(obj, "mutex_spins",  json_integer(items[i].mutex_innards.__spins));
            json_object_set(obj, "mutex_elision",  json_integer(items[i].mutex_innards.__elision));
#endif
        }

        json_array_append(arr, obj);
    }

    char *dot = strrchr(data_filename, '.');
    if (dot)
        *dot = 0x00;

    char *json_filename = nullptr;
    asprintf(&json_filename, "%s.json", data_filename);

    json_dump_file(arr, json_filename, JSON_COMPACT);

    json_decref(arr);

    printf("Output written to %s\n", json_filename);

    return 0;
}
