include(FetchContent)

cmake_policy(SET CMP0135 NEW)

FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/releases/download/v1.17.0/googletest-1.17.0.tar.gz
        URL_HASH SHA256=65fab701d9829d38cb77c14acdc431d2108bfdbf8979e40eb8ae567edf10b27c
)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

set(ChaosTests_SOURCE Hash/Md4HasherTests.cpp
                      Hash/Md5HasherTests.cpp
                      Hash/Sha1HasherTests.cpp
                      Mac/HmacTests.cpp
                      Cipher/Arc4GenTests.cpp
                      Cipher/Arc4CryptTests.cpp
                      Service/SeArrayTests.cpp)

add_executable(ChaosTests ${ChaosTests_SOURCE})
target_link_libraries(ChaosTests gtest gtest_main)
target_include_directories(ChaosTests PRIVATE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/Chaos>
)

include(GoogleTest)

gtest_discover_tests(ChaosTests)
