g++ -ggdb3 -fPIC -std=c++1y lock_tracer.cpp -shared -o lock_tracer.so -Wl,--whole-archive -ljansson -Wl,--no-whole-archive -ldl
