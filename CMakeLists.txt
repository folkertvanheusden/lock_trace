# (C) 2021 by folkert@vanheusden.com
# released under Apache license v2.0

cmake_minimum_required(VERSION 3.9.4)

project(lock_tracer VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_C_STANDARD 99)

add_definitions("-D_FILE_OFFSET_BITS=64")

set(CMAKE_BUILD_TYPE Debug)

add_compile_options(-Wall -pedantic)

add_library(lock_tracer SHARED
	lock_tracer.cpp
	)

add_executable(test
	test.c
	)

add_executable(analyzer
    analyzer.cpp
    )

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads)
target_link_libraries(lock_tracer Threads::Threads)

target_link_libraries(test Threads::Threads)

include(FindPkgConfig)

pkg_check_modules(JANSSON REQUIRED jansson)
target_link_libraries(lock_tracer ${JANSSON_LIBRARIES})
target_include_directories(lock_tracer PUBLIC ${JANSSON_INCLUDE_DIRS})
target_compile_options(lock_tracer PUBLIC ${JANSSON_CFLAGS_OTHER})

pkg_check_modules(LIBUNWIND REQUIRED libunwind)
target_link_libraries(lock_tracer ${LIBUNWIND_LIBRARIES})
target_include_directories(lock_tracer PUBLIC ${LIBUNWIND_INCLUDE_DIRS})
target_compile_options(lock_tracer PUBLIC ${LIBUNWIND_CFLAGS_OTHER})

target_link_libraries(analyzer ${JANSSON_LIBRARIES})
target_include_directories(analyzer PUBLIC ${JANSSON_INCLUDE_DIRS})
target_compile_options(analyzer PUBLIC ${JANSSON_CFLAGS_OTHER})

pkg_check_modules(GVC libgvc)
target_link_libraries(analyzer ${GVC_LIBRARIES})
target_include_directories(analyzer PUBLIC ${GVC_INCLUDE_DIRS})
target_compile_options(analyzer PUBLIC ${GVC_CFLAGS_OTHER})

target_link_libraries(lock_tracer -ldl)
target_link_libraries(lock_tracer -rdynamic)

target_link_libraries(test -rdynamic)

target_compile_options(lock_tracer PRIVATE "-Wall")
target_compile_options(lock_tracer PRIVATE "-pedantic")
target_compile_options(test PRIVATE "-Wall")
target_compile_options(analyzer PRIVATE "-Wall")
target_compile_options(analyzer PRIVATE "-pedantic")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Ofast -ggdb3")
set(CMAKE_C_FLAGS "${CMAKE_CXX_FLAGS} -Ofast -ggdb3")
SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -ggdb3")

configure_file(config.h.in config.h)
target_include_directories(analyzer PUBLIC "${PROJECT_BINARY_DIR}")
target_include_directories(lock_tracer PUBLIC "${PROJECT_BINARY_DIR}")
