# SPDX-License-Identifier: MIT
#
# Microfoam - firmware delta update library.
# Tiny bubbles. Tiny footprint. Full-strength upgrade.

cmake_minimum_required(VERSION 3.15)

project(microfoam
    VERSION 1.9.1
    DESCRIPTION "Firmware delta update library for resource-constrained microcontrollers"
    LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# ------------------------------------------------------------------ options
option(MCF_BUILD_TESTS   "Build the host test suite"                  ON)
option(MCF_WERROR        "Treat warnings as errors"                   ON)
option(MCF_STRICT        "Add -Wconversion and friends"               ON)
option(MCF_ENABLE_SODIUM "Build the vetted libsodium Ed25519 adapter" OFF)
if(MCF_ENABLE_SODIUM AND NOT MCF_BUILD_TESTS)
    message(STATUS "libsodium adapter enabled; applications must configure the HAL verify callback to mcf_sodium_verify")
endif()

# The coverage-guided fuzz target needs Clang's libFuzzer plus the ASan/UBSan
# runtimes, so it is opt-in and self-contained: it compiles the parser source it
# exercises with the sanitizers, leaving every other target untouched.
option(MCF_BUILD_FUZZER "Build the coverage-guided MFP2 parser fuzz target (requires Clang)" OFF)

# Sanitize the whole host suite, not just the parser. The fuzzer above covers
# one function; this option covers every test target, which is where the
# engine, the session state machine, the codec adapters and the container
# parser all meet real inputs. Off by default because the runtimes are not
# available on every toolchain (notably MinGW-w64 GCC); the CI job that
# enables it uses Clang. Requires a compiler that ships the ASan/UBSan
# runtimes - the configure step fails with a clear message otherwise rather
# than producing a half-instrumented build.
option(MCF_SANITIZE "Build the host test suite with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

# ------------------------------------------------------------------ sources
# An explicit list. A recursive glob would drag experimental or rejected
# implementations into a device build that has no use for them.
set(MCF_SOURCES
    src/mcf_codec.c
    src/mcf_container.c
    src/mcf_engine.c
    src/mcf_hal.c
    src/mcf_session.c
    src/mcf_util.c
    src/mcf_codec_lz4.c
    src/mcf_codec_raw.c
    src/mcf_v2.c
    src/mcf_v2_session.c)

# LZMA is opt-in and fully supported when enabled: a patch declaring LZMA is
# rejected with MCF_E_UNSUPPORTED unless this option is ON, because the decoder
# adds a probability table and dictionary to the workspace. The decoder is the
# vendored LZMA SDK (third_party/lzma-sdk, public domain); see
# docs/lzma-history.md for why the from-scratch decoder was retired.
option(MCF_ENABLE_LZMA "Build the LZMA decoder (vendored LZMA SDK)" OFF)
if(MCF_ENABLE_LZMA)
    list(APPEND MCF_SOURCES src/mcf_lzma.c)
endif()

set(MCF_HEADERS include/microfoam.h include/microfoam_v2.h)
if(MCF_ENABLE_SODIUM)
    list(APPEND MCF_HEADERS include/microfoam_sodium.h)
endif()

# ------------------------------------------------------------------ warnings
set(MCF_WARNINGS
    -Wall
    -Wextra
    -Wshadow
    -Wundef
    -Wcast-qual
    -Wpointer-arith
    -Wstrict-prototypes
    -Wmissing-prototypes)

if(MCF_STRICT)
    list(APPEND MCF_WARNINGS -Wconversion -Wsign-conversion -Wdouble-promotion)
endif()

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    list(APPEND MCF_WARNINGS
        -Werror=return-type
        -Wformat=2
        -Wvla
        -Wwrite-strings)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        list(APPEND MCF_WARNINGS -Wcast-function-type)
    endif()
endif()

if(MSVC)
    set(MCF_WARNINGS /W4)
    if(MCF_WERROR)
        list(APPEND MCF_WARNINGS /WX)
    endif()
else()
    if(MCF_WERROR)
        list(APPEND MCF_WARNINGS -Werror)
    endif()
endif()

# ------------------------------------------------------------------ sanitizers
# One flag list, applied to every target through MCF_WARNINGS so the library
# and the tests that exercise it are instrumented by the same build. MSVC
# spells these differently and is not a target for this option.
if(MCF_SANITIZE)
    if(MSVC)
        message(FATAL_ERROR "MCF_SANITIZE is not supported with MSVC; use Clang or GCC")
    endif()
    set(MCF_SANITIZE_FLAGS
        -fsanitize=address,undefined
        -fno-omit-frame-pointer
        -fno-sanitize-recover=all)
    set(MCF_SANITIZE_LINK_FLAGS ${MCF_SANITIZE_FLAGS})

    # The runtimes are not present on every toolchain, and without this probe
    # the failure surfaces at link time as a missing -lasan, far from the
    # option that caused it. Verified missing on both MinGW-w64 GCC and
    # MSYS2 Clang for Windows (the mingw compiler-rt package ships fuzzer and
    # profile runtimes but not asan); the CI job that enables this option runs
    # on Linux, where Clang and GCC both provide them.
    include(CheckCSourceCompiles)
    set(CMAKE_REQUIRED_FLAGS "${MCF_SANITIZE_LINK_FLAGS}")
    check_c_source_compiles("int main(void){return 0;}" MCF_SANITIZER_RUNTIME_AVAILABLE)
    unset(CMAKE_REQUIRED_FLAGS)
    if(NOT MCF_SANITIZER_RUNTIME_AVAILABLE)
        message(FATAL_ERROR
            "MCF_SANITIZE requires the AddressSanitizer and UBSan runtimes, "
            "which this toolchain does not provide. Use a Linux or macOS "
            "Clang/GCC, or leave MCF_SANITIZE=OFF. On Windows the mingw "
            "compiler-rt package does not ship the ASan runtime.")
    endif()

    list(APPEND MCF_WARNINGS ${MCF_SANITIZE_FLAGS})
    message(STATUS "Sanitizers enabled: address,undefined (unrecoverable)")
endif()

if(MCF_ENABLE_SODIUM)
    find_path(SODIUM_INCLUDE_DIR sodium.h)
    find_library(SODIUM_LIBRARY NAMES sodium libsodium)
    if(NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARY)
        message(FATAL_ERROR "MCF_ENABLE_SODIUM requires libsodium headers and library")
    endif()
    list(APPEND MCF_SOURCES src/mcf_sodium.c include/microfoam_sodium.h)
endif()

add_library(microfoam STATIC ${MCF_SOURCES} ${MCF_HEADERS})
add_library(microfoam::microfoam ALIAS microfoam)

target_include_directories(microfoam PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)

target_compile_options(microfoam PRIVATE ${MCF_WARNINGS})

# The sanitizer runtimes must be linked into every executable, and the tests
# link the static library, so this propagates rather than sitting on the
# library alone. INTERFACE so the test targets inherit it.
if(MCF_SANITIZE)
    target_compile_options(microfoam INTERFACE ${MCF_SANITIZE_FLAGS})
    target_link_options(microfoam INTERFACE ${MCF_SANITIZE_LINK_FLAGS})
endif()

if(MCF_ENABLE_SODIUM)
    target_include_directories(microfoam PRIVATE ${SODIUM_INCLUDE_DIR})
    target_link_libraries(microfoam PUBLIC ${SODIUM_LIBRARY})
    target_compile_definitions(microfoam PUBLIC MCF_ENABLE_SODIUM=1)
endif()

if(MCF_ENABLE_LZMA)
    # The SDK is vendored unmodified; it is compiled as its own object library
    # with relaxed warnings so our strict -Werror set does not police
    # third-party code we do not edit.
    add_library(mcf_lzma_sdk OBJECT third_party/lzma-sdk/LzmaDec.c)
    target_include_directories(mcf_lzma_sdk PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lzma-sdk)
    if(MSVC)
        target_compile_options(mcf_lzma_sdk PRIVATE /W3)
    else()
        target_compile_options(mcf_lzma_sdk PRIVATE -Wall -Wextra)
    endif()

    target_sources(microfoam PRIVATE
        $<TARGET_OBJECTS:mcf_lzma_sdk>)
    target_include_directories(microfoam PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lzma-sdk)
    target_compile_definitions(microfoam PRIVATE MCF_ENABLE_LZMA=1)
endif()


set_target_properties(microfoam PROPERTIES
    C_VISIBILITY_PRESET hidden
    VERSION ${PROJECT_VERSION})

# ------------------------------------------------------------------ tests
if(MCF_BUILD_TESTS)
    enable_testing()

    if(MCF_ENABLE_SODIUM)
        add_executable(sodium_rfc_test tests/sodium_rfc_test.c)
        target_link_libraries(sodium_rfc_test PRIVATE microfoam)
        target_include_directories(sodium_rfc_test PRIVATE ${SODIUM_INCLUDE_DIR})
        target_compile_options(sodium_rfc_test PRIVATE ${MCF_WARNINGS})
        add_test(NAME sodium_rfc_test COMMAND sodium_rfc_test)

        # The parser/session boundary is valid in every build; this test adds a
        # real host-produced signed+encrypted patch when the optional crypto
        # provider and host PyNaCl are both available.
        add_executable(mfp2_boundary_test tests/mfp2_boundary_test.c)
        target_link_libraries(mfp2_boundary_test PRIVATE microfoam)
        target_include_directories(mfp2_boundary_test PRIVATE ${SODIUM_INCLUDE_DIR})
        target_compile_options(mfp2_boundary_test PRIVATE ${MCF_WARNINGS})
    endif()

    add_executable(v2_format_test tests/v2_format_test.c)
    target_link_libraries(v2_format_test PRIVATE microfoam)
    target_compile_options(v2_format_test PRIVATE ${MCF_WARNINGS})
    add_test(NAME v2_format_test COMMAND v2_format_test)

    # The parser is the one surface that consumes attacker-controlled bytes, so
    # it gets a property oracle (tests/v2_parse_fixture.h) shared with a fuzz
    # target. This portable smoke target runs those assertions on every platform
    # and needs no sanitizer runtime, so the gate exists even without Clang.
    add_executable(v2_fuzz_smoke tests/fuzz_v2_parse.c)
    target_link_libraries(v2_fuzz_smoke PRIVATE microfoam)
    target_compile_definitions(v2_fuzz_smoke PRIVATE MCF_FUZZ_STANDALONE=1)
    target_compile_options(v2_fuzz_smoke PRIVATE ${MCF_WARNINGS})
    add_test(NAME v2_fuzz_smoke COMMAND v2_fuzz_smoke)

    if(MCF_BUILD_FUZZER)
        if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
            message(FATAL_ERROR "MCF_BUILD_FUZZER requires Clang for libFuzzer")
        endif()
        # The parser source is compiled into the target with the sanitizers, so a
        # fault inside mcf_v2_parse is caught, not merely one in the harness. No
        # MCF_FUZZ_STANDALONE here: the fuzzer runtime supplies main().
        add_executable(v2_parse_fuzzer tests/fuzz_v2_parse.c src/mcf_v2.c)
        target_include_directories(v2_parse_fuzzer PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_compile_options(v2_parse_fuzzer PRIVATE
            ${MCF_WARNINGS} -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
        target_link_options(v2_parse_fuzzer PRIVATE
            -fsanitize=fuzzer,address,undefined)
    endif()

    add_executable(hal_concurrency_test tests/hal_concurrency_test.c)
    target_link_libraries(hal_concurrency_test PRIVATE microfoam)
    target_compile_options(hal_concurrency_test PRIVATE ${MCF_WARNINGS})
    add_test(NAME hal_concurrency_test COMMAND hal_concurrency_test)

    add_executable(custom_codec_test tests/custom_codec_test.c)
    target_link_libraries(custom_codec_test PRIVATE microfoam)
    target_compile_options(custom_codec_test PRIVATE ${MCF_WARNINGS})
    add_test(NAME custom_codec_test COMMAND custom_codec_test)

    add_executable(microfoam_tests tests/test_microfoam.c)
    target_link_libraries(microfoam_tests PRIVATE microfoam)
    target_compile_options(microfoam_tests PRIVATE ${MCF_WARNINGS})
    add_test(NAME microfoam_tests COMMAND microfoam_tests)

    # LZMA conformance: 67 vectors generated by liblzma (the reference
    # implementation) x 5 block sizes. This is the gate that makes the LZMA
    # codec supported rather than experimental. The vectors are generated, not
    # committed (host/lzma_vectors.bin is in .gitignore), so the test needs
    # Python's lzma module - which is also what makes it a reference test.
    if(MCF_ENABLE_LZMA)
        add_executable(lzma_conformance_test tests/lzma_conformance_test.c)
        target_link_libraries(lzma_conformance_test PRIVATE microfoam)
        target_compile_options(lzma_conformance_test PRIVATE ${MCF_WARNINGS})
        target_include_directories(lzma_conformance_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)

        add_executable(lzma_policy_test tests/lzma_policy_test.c)
        target_link_libraries(lzma_policy_test PRIVATE microfoam)
        target_compile_options(lzma_policy_test PRIVATE ${MCF_WARNINGS})
        target_include_directories(lzma_policy_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        add_test(NAME lzma_policy_test COMMAND lzma_policy_test)

        find_package(Python3 COMPONENTS Interpreter)
        if(Python3_Interpreter_FOUND)
            set(MCF_LZMA_VECTORS ${CMAKE_CURRENT_BINARY_DIR}/lzma_vectors.bin)
            add_test(NAME lzma_vectors
                     COMMAND ${Python3_EXECUTABLE}
                             ${CMAKE_CURRENT_SOURCE_DIR}/host/lzma_vectors.py
                             --out ${MCF_LZMA_VECTORS})
            add_test(NAME lzma_conformance_test
                     COMMAND lzma_conformance_test ${MCF_LZMA_VECTORS})
            set_tests_properties(lzma_conformance_test PROPERTIES
                DEPENDS lzma_vectors)
        else()
            message(STATUS
                "Python3 not found: lzma_conformance_test is built but not registered")
        endif()
    endif()

    # Cross-implementation test: a patch produced by the Python host tool is
    # applied by the C library. A library verified only against its own encoder
    # proves nothing about the format, so this is the check that matters most.
    find_package(Python3 COMPONENTS Interpreter)
    if(Python3_Interpreter_FOUND)
        if(MCF_ENABLE_SODIUM)
            execute_process(
                COMMAND ${Python3_EXECUTABLE} -c "import nacl.bindings"
                RESULT_VARIABLE MCF_PYNACL_RESULT
                OUTPUT_QUIET ERROR_QUIET)
            if(MCF_PYNACL_RESULT EQUAL 0)
                add_test(NAME mfp2_host_to_session
                    COMMAND ${CMAKE_COMMAND}
                        -DOLD=${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/old.bin
                        -DNEW=${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/new.bin
                        -DMCF=$<TARGET_FILE:mfp2_boundary_test>
                        -DPY=${Python3_EXECUTABLE}
                        -DTOOL=${CMAKE_CURRENT_SOURCE_DIR}/host/microfoam.py
                        -DWORK=${CMAKE_CURRENT_BINARY_DIR}/mfp2
                        -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/mfp2_boundary_test.cmake)
            else()
                message(STATUS "PyNaCl unavailable: MFP2 host-to-session test is not registered")
            endif()
        endif()

        add_executable(cross_test tests/cross_test.c)
        target_link_libraries(cross_test PRIVATE microfoam)
        target_compile_options(cross_test PRIVATE ${MCF_WARNINGS})

        # The cross test signs a patch and requires the device to refuse it
        # (fail-closed). The signing seed is generated here, in the build tree,
        # rather than read from tests/fixtures/key.priv: that path is
        # gitignored, so on a fresh clone - which is what CI is - it does not
        # exist, and the check used to skip itself rather than fail. Generating
        # it makes the gate unconditional for every developer and every runner.
        set(MCF_TEST_KEY "${CMAKE_CURRENT_BINARY_DIR}/test-keys/key.priv")
        execute_process(
            COMMAND ${Python3_EXECUTABLE} -c
                "import pathlib,sys; p=pathlib.Path(sys.argv[1]); p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(bytes(range(32)))"
                "${MCF_TEST_KEY}"
            RESULT_VARIABLE MCF_TEST_KEY_RC)
        if(NOT MCF_TEST_KEY_RC EQUAL 0)
            message(FATAL_ERROR "could not generate the cross-test signing key")
        endif()

        add_test(NAME host_selftest
                 COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/host/selftest.py)

        # The README states a check count per suite. Nothing checked those
        # numbers, so they drifted (host_selftest was documented as 101 while
        # reporting 104). This compares the documented figures against what the
        # suites in this build tree actually report, so a stated number cannot
        # silently stop being true. It depends on the C suites, so it runs after
        # they are built.
        add_test(NAME documented_counts
                 COMMAND ${Python3_EXECUTABLE}
                         ${CMAKE_CURRENT_SOURCE_DIR}/host/check_counts.py
                         --build ${CMAKE_CURRENT_BINARY_DIR})
        set_tests_properties(documented_counts PROPERTIES
            DEPENDS "microfoam_tests;custom_codec_test;hal_concurrency_test;v2_format_test;host_selftest")

        add_test(NAME cross_test
                 COMMAND ${CMAKE_COMMAND}
                         -DOLD=${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/old.bin
                         -DNEW=${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/new.bin
                         -DKEY=${MCF_TEST_KEY}
                         -DMCF=$<TARGET_FILE:cross_test>
                         -DPY=${Python3_EXECUTABLE}
                         -DTOOL=${CMAKE_CURRENT_SOURCE_DIR}/host/microfoam.py
                         -DWORK=${CMAKE_CURRENT_BINARY_DIR}/cross
                         -DCODEC=lz4
                         -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/cross_test.cmake)

        # The README's quick start is a device configuration paired with a host
        # command, and the two must agree on the block size or the documented
        # patch cannot apply. Nothing checked the pair, and it drifted. This
        # builds the documented patch and applies it at the documented settings,
        # then confirms the check can fail, so the example stays runnable.
        add_test(NAME quickstart_config
                 COMMAND ${Python3_EXECUTABLE}
                         ${CMAKE_CURRENT_SOURCE_DIR}/host/check_quickstart.py
                         --cross-test $<TARGET_FILE:cross_test>)

        # The same cross test with a raw (uncompressed) patch: proves the
        # identity codec round-trips through the C session.
        add_test(NAME cross_test_raw
                 COMMAND ${CMAKE_COMMAND}
                         -DOLD=${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/old.bin
                         -DNEW=${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/new.bin
                         -DKEY=${MCF_TEST_KEY}
                         -DMCF=$<TARGET_FILE:cross_test>
                         -DPY=${Python3_EXECUTABLE}
                         -DTOOL=${CMAKE_CURRENT_SOURCE_DIR}/host/microfoam.py
                         -DWORK=${CMAKE_CURRENT_BINARY_DIR}/cross
                         -DCODEC=raw
                         -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/cross_test.cmake)

        # The same cross test with an LZMA patch, when the decoder is built in.
        # This is the check that proves host-produced LZMA patches apply
        # byte-exact on the device path.
        if(MCF_ENABLE_LZMA)
            add_test(NAME cross_test_lzma
                     COMMAND ${CMAKE_COMMAND}
                             -DOLD=${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/old.bin
                             -DNEW=${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/new.bin
                             -DKEY=${MCF_TEST_KEY}
                             -DMCF=$<TARGET_FILE:cross_test>
                             -DPY=${Python3_EXECUTABLE}
                             -DTOOL=${CMAKE_CURRENT_SOURCE_DIR}/host/microfoam.py
                             -DWORK=${CMAKE_CURRENT_BINARY_DIR}/cross
                             -DCODEC=lzma
                             -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/cross_test.cmake)
        endif()
    endif()
endif()

# ------------------------------------------------------------------ install
include(GNUInstallDirs)
install(TARGETS microfoam EXPORT microfoamTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${MCF_HEADERS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT microfoamTargets
        FILE microfoamTargets.cmake
        NAMESPACE microfoam::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/microfoam)
