include(FetchContent)

FetchContent_Declare(
    benchmark
    GIT_REPOSITORY https://github.com/google/benchmark.git
    GIT_TAG        v1.9.5
)

set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(benchmark)

file(GLOB_RECURSE FDPI_BENCH_SOURCES CONFIGURE_DEPENDS *.cpp)

add_executable(fdpi_benchmarks ${FDPI_BENCH_SOURCES})

target_link_libraries(fdpi_benchmarks
    PRIVATE
        fdpi::fdpi
        benchmark::benchmark
        benchmark::benchmark_main
)
