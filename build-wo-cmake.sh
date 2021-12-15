#! /bin/sh

g++ -fPIC -std=c++17 lock_tracer.cpp -shared -o lock_tracer.so -Wl,--whole-archive -ljansson -Wl,--no-whole-archive
