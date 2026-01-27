include(FetchContent)

cmake_policy(SET CMP0135 NEW)

FetchContent_Declare(
        googlebenchmark
        URL https://git.hashlag.net/hashlag/chaos-deps/raw/branch/main/google_benchmark/benchmark-1.9.5.tar.gz
        URL_HASH SHA256=9631341c82bac4a288bef951f8b26b41f69021794184ece969f8473977eaa340
)

set(BENCHMARK_ENABLE_WERROR OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googlebenchmark)

set(ChaosBenches_SOURCE BenchmarkMain.cpp
                        Hash/Md4HasherBenches.cpp
                        Hash/Md5HasherBenches.cpp
                        Hash/Sha1HasherBenches.cpp)

add_executable(ChaosBenches ${ChaosBenches_SOURCE})
target_link_libraries(ChaosBenches benchmark::benchmark)
target_include_directories(ChaosBenches PRIVATE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/Chaos>
)
