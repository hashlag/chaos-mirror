include(FetchContent)

cmake_policy(SET CMP0135 NEW)

FetchContent_Declare(
        googletest
        URL https://git.hashlag.net/hashlag/chaos-deps/raw/branch/main/google_googletest/googletest-1.17.0.tar.gz
        URL_HASH SHA256=65fab701d9829d38cb77c14acdc431d2108bfdbf8979e40eb8ae567edf10b27c
)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

set(ChaosTests_SOURCE SanCallbacks.cpp
                      Hash/Md4HasherTests.cpp
                      Hash/Md5HasherTests.cpp
                      Hash/Sha1HasherTests.cpp
                      Mac/HmacTests.cpp
                      Cipher/Arc4GenTests.cpp
                      Cipher/Arc4CryptTests.cpp
                      Cipher/DesCryptTests.cpp
                      Cipher/EcbModeTests.cpp
                      Padding/PadderPkcs7Tests.cpp
                      Padding/PadderIso7816Tests.cpp
                      Service/SeArrayTests.cpp
                      Service/ChaosExceptionTests.cpp)

add_executable(ChaosTests ${ChaosTests_SOURCE})
target_link_libraries(ChaosTests gtest gtest_main)
target_include_directories(ChaosTests PRIVATE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/Chaos>
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/ChaosTests>
)

target_compile_options(ChaosTests PRIVATE -Wunused -Werror=unused)

option(CHAOS_COVERAGE "Enable coverage" OFF)
option(CHAOS_ASANUBSAN "Enable ASan and UBSan" OFF)

if(CHAOS_COVERAGE)
    target_compile_options(ChaosTests PRIVATE --coverage)
    target_link_options(ChaosTests PRIVATE --coverage)
endif()

if(CHAOS_ASANUBSAN)
    target_compile_options(ChaosTests PRIVATE -fsanitize=address,undefined -fno-sanitize-recover=all)
    target_link_options(ChaosTests PRIVATE -fsanitize=address,undefined -fno-sanitize-recover=all)
endif()

include(GoogleTest)

gtest_discover_tests(ChaosTests)
