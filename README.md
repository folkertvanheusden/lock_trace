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
'elfutils' package.


building
--------
  mkdir build
  cd build
  cmake ..
  make


usage
-----
Make sure your system can create core files:

  ulimit -c unlimited

Then:

  LD_PRELOAD=/path/to/liblock_tracer.so ./my_program

It should terminate with a core-dump.

If possible(!), modify your program that it invokes exit(0)
before clean-up. In exit(0) (or regular exit) a dump will be
made of the trace (to be analyzed later with 'analyze.py').
If you do this before all data is freed, then analysis by
yourself later on of the core-file will be more easy. Like
finding information about mutexes.


Show analysis:
  ./analyze.py /path/to/core < dump.dat

That may display something like:

```
  Double lock:  50138 0x7fff10927b20 426911 /home/folkert/Projects/lock_tracer/lock_tracer.cpp:82:13,/home/folkert/Projects/lock_tracer/lock_tracer.cpp:101:36,/home/folkert/Projects/lock_tracer/test.c:48:2,../csu/libc-start.c:332:16,??:0


  Invalid unlock:  50140 0x7fff10927b20 426911 /home/folkert/Projects/lock_tracer/lock_tracer.cpp:82:13,/home/folkert/Projects/lock_tracer/lock_tracer.cpp:108:38,/home/folkert/Projects/lock_tracer/test.c:50:2,../csu/libc-start.c:332:16,??:0
```

* 50138 / 50140 is the invocation number
* 0x7fff10927b20 is the address of the mutex
* 426911 is the TID (thread id)


notes
-----
A single atomic integer is used to index the history-buffer: this
will change timing. Also the tracing itself is 'heavy' (cpu-time
wise). You can reduce that a bit by disabling the backtrace (see
performance section below).

You may want to look at the 'CHANGE THESE' defines at the top of
lock_tracer.cpp to suit your needs.

If your program suddenly hangs where it did not before, then
this may be caused by the version of 'backtrace' in libgcc
using 'pthread_mutex' underneath.
There are two solutions:
- disable backrace recording (see notes on WITH_BACKTRACE below)
- uncomment PREVENT_RECURSION which adds an extra check to see
  if there's a loop

Note that capturing pthread_exit may introduce inaccuracies: it
assumes that the cleaner(s) (see pthread_cleanup_push) will
unlock any left over locked mutex.


performance
-----------
without any wrappers or testers: 22547276/s
lock_tracer                    :   301873/s
lock_tracer without backtrace' :  2803110/s  (comment out the WITH_BACKTRACE define in lock_trace.cpp)
valgrind with drd              :   113432/s
valgrind with helgrind         :    89817/s

Note: valgrind affects *all* performance while lock_tracer only
the locking/unlocking calls.


(C) 2021 by folkert@vanheusden.com
Released under GPL v3.0.

If you like to thank me, please be kind to other living things instead.
