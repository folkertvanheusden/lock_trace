what does it do
---------------
It traces usage of pthread_mutex_lock and pthread_mutex_unlock
(and pthread_mutex_trylock).
These are also used underneath by e.g. std::mutex.
It can then show if certain invalid actions were performed on
the mutexes used.


requirements
------------
analyze.py needs the '/usr/bin/eu-addr2line' program from the
'elfutils' package. Also lock_tracer.cpp requires 'libc6-dev'
and 'libjansson-dev' (glibc-devel and jansson-devel on rpm
systems) packages to build.


building
--------
```
mkdir build
cd build
cmake ..
make
```

If the cmake on your system is too old (or not installed), try:
./build-wo-cmake.sh


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

Convert binary data-dump to json (which will be processed
by analyze.py):

```
./dat_to_json dump.dat
```

Show analysis:

```
./analyze.py -c core -t dump.dat -f report.html
```

This will generate an html-file that can be opened with a regular
web-browser.

You can also set the 'ENFORCE_ERR_CHK' environment variable. In that
case every mutex that is not error-checking will be replaced by an
error checking mutex. Note that this modifies the mutexes in place.

Consider using the 'analyzer'-branch on github.com. That version is
implemented in c++ and an order of magnitude faster than the python
version (altough not feature complete yet).


notes
-----
* A single atomic integer is used to index the history-buffer: this
  will change timing. Also the tracing itself is 'heavy' (cpu-time
  wise). You can reduce that a bit by disabling the backtrace (see
  performance section below).

* You may want to look at the defines in 'config.h' to enable- or
  disable certain functionality of lock_tracer. Disabling e.g.
  timing measurements makes it faster. Also using
  'SHALLOW_BACKTRACE' helps for speed.

* If your program suddenly hangs where it did not before, then
  this may be caused by the version of 'backtrace' in libgcc
  using 'pthread_mutex' underneath.
  There are two solutions:
  * disable backrace recording (see notes on WITH_BACKTRACE below)
  * uncomment PREVENT_RECURSION which makes it do a "shallow back-
    trace" (1 record)

* Note that capturing pthread_exit may introduce inaccuracies: it
  assumes that the cleaner(s) (see pthread_cleanup_push) will
  unlock any left over locked mutex.

* "still locked" can also mean that a mutex was destroyed before
  being unlocked.


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
