g++ -ggdb3 -fPIC -std=c++1y lock_tracer.cpp -shared -o lock_tracer.so -Wl,--whole-archive -ljansson -Wl,--no-whole-archive -ldl

g++ -std=c++1y -ggdb3 -Ofast dat_to_json.cpp -ljansson -o dat_to_json
