what does it do
---------------
It traces usage of mutex and read/write-lock usage.
These are also used underneath by e.g. std::mutex.
It can then show if certain invalid actions were performed on
the mutexes used. Also some basic statistics (like average
held-durations).


requirements
------------
analyzer needs the '/usr/bin/eu-addr2line' program from the
'elfutils' package. Also lock_tracer.cpp requires 'libc6-dev',
'libjansson-dev', 'libunwind-dev' and 'libgraphviz-dev' ('glibc-
devel', 'jansson-devel', 'libunwind-devel' and 'graphviz-devel'
on rpm systems) packages to build. Note that 'libgraphviz-dev'
is optional.


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
Make sure your system can create core dump files:

```
ulimit -c unlimited
```
The lock_tracer wrapper will alert you if you did not enable
core dump files.

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
./analyzer -c core -t dump.dat -f report.html
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
  wise). You can reduce that a bit by disabling the backtrace.

* You may want to look at the defines in 'config.h.in' to enable-
  or disable certain functionality of lock_tracer. Disabling e.g.
  timing measurements makes it faster. Also using
  'SHALLOW_BACKTRACE' helps for speed.

* Note that capturing pthread_exit may introduce inaccuracies: it
  assumes that the cleaner(s) (see pthread_cleanup_push) will
  unlock any left over locked mutex.

* "still locked" can also mean that a mutex was destroyed before
  being unlocked.

* if backtraces make no sense, consider compiling the program
  under test with -fno-inline


example
-------
* https://vanheusden.com/lock_tracer/example-report.html


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
