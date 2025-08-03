include(FetchContent)

FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.17.0
)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(ChaosTests Md4HasherTests.cpp Md5HasherTests.cpp)
target_link_libraries(ChaosTests gtest gtest_main)
target_include_directories(ChaosTests PRIVATE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/Chaos>
)

include(GoogleTest)

gtest_discover_tests(ChaosTests)
