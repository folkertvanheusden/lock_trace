what does it do
---------------
It traces usage of pthread_mutex_lock and pthread_mutex_unlock
(and pthread_mutex_trylock).
These are also used underneath by e.g. std::mutex.
It can then show if certain invalid actions were performed on
the mutexes used.
rwlocks are not yet supported.


requirements
------------
analyze.py needs the '/usr/bin/eu-addr2line' program from the
'elfutils' package. Also lock_tracer.cpp requires 'libc6-dev'
and 'libjansson-dev' packages to build.


building
--------
```
mkdir build
cd build
cmake ..
make
```


usage
-----
Make sure your system can create core files:

```
ulimit -c unlimited
```

If possible, link your program with -rdynamic and compile
and link it with -ggdb3.

Then:

```
LD_PRELOAD=/path/to/liblock_tracer.so ./my_program
```

It should terminate with a core-dump.

If possible(!), modify your program that it invokes exit(0)
before clean-up. In exit(0) (or regular exit) a dump will be
made of the trace (to be analyzed later with 'analyze.py').
If you do this before all data is freed, then analysis by
yourself later on of the core-file will be easier. Like
finding information about mutexes.

You can change the maximum number of trace records by
setting the 'TRACE_N_RECORDS' environment variable. Defeault
is 16777216 records.


Show analysis:

```
./analyze.py -c core -t dump.dat -f report.html
```

This will generate an html-file that can be opened with a regular
web-browser.

You can also set the 'ENFORCE_ERR_CHK' environment variable. In that
case every mutex that is not error-checking will be replaced by an
error checking mutex. Note that this modifies the mutexes in place.


notes
-----
* A single atomic integer is used to index the history-buffer: this
  will change timing. Also the tracing itself is 'heavy' (cpu-time
  wise). You can reduce that a bit by disabling the backtrace (see
  performance section below).

* You may want to look at the 'CHANGE THESE' defines at the top of
  lock_tracer.cpp to suit your needs.

* If your program suddenly hangs where it did not before, then
  this may be caused by the version of 'backtrace' in libgcc
  using 'pthread_mutex' underneath.
  There are two solutions:
  * disable backrace recording (see notes on WITH_BACKTRACE below)
  * uncomment PREVENT_RECURSION which adds an extra check to see
    if there's a loop

* Note that capturing pthread_exit may introduce inaccuracies: it
  assumes that the cleaner(s) (see pthread_cleanup_push) will
  unlock any left over locked mutex.


performance
-----------
```
without any wrappers or testers: 51496k/s
lock_tracer                    :   373k/s
lock_tracer without backtrace' :  7320k/s  (comment out the WITH_BACKTRACE line in lock_trace.cpp)
valgrind with drd              :   113k/s
valgrind with helgrind         :    89k/s
```

Note: valgrind affects *all* performance while lock_tracer only
affects the locking/unlocking calls.


similar software
----------------
* mutrace, http://0pointer.de/blog/projects/mutrace.html
* valgrind, https://valgrind.org/


code analysis of this program
-----------------------------
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/folkertvanheusden/lock_trace.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/folkertvanheusden/lock_trace/context:python)
[![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/folkertvanheusden/lock_trace.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/folkertvanheusden/lock_trace/context:cpp)


(C) 2021 by folkert@vanheusden.com
Released under Apache license v2.0.
