# SPDX-License-Identifier: MIT
#
# Microfoam - firmware delta update library.
# Tiny bubbles. Tiny footprint. Full-strength upgrade.

cmake_minimum_required(VERSION 3.15)

project(microfoam
    VERSION 0.1.0
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
    src/mcf_v2.c)

# LZMA is opt-in, experimental, and not shippable; see contrib/lzma-wip/README.md.
# Off by default, and a patch declaring LZMA is rejected unless this development
# decoder is explicitly enabled. The current WIP result is 133/335 conformance
# cases; enabling it is for investigation only and must never be a release default.
option(MCF_ENABLE_LZMA "Build the work-in-progress LZMA decoder (development only)" OFF)
if(MCF_ENABLE_LZMA)
    list(APPEND MCF_SOURCES ${CMAKE_CURRENT_LIST_DIR}/contrib/lzma-wip/mcf_lzma.c)
    set(MCF_LZMA_DIR ${CMAKE_CURRENT_LIST_DIR}/contrib/lzma-wip)
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

if(MCF_ENABLE_SODIUM)
    target_include_directories(microfoam PRIVATE ${SODIUM_INCLUDE_DIR})
    target_link_libraries(microfoam PUBLIC ${SODIUM_LIBRARY})
    target_compile_definitions(microfoam PUBLIC MCF_ENABLE_SODIUM=1)
endif()

# The LZMA decoder lives outside src/ because it is unverified, so it needs its
# own include path and a define that makes the registry pick it up. Both are
# applied here rather than next to the option, because the target does not
# exist until add_library has run.
if(MCF_ENABLE_LZMA)
    # The decoder sits outside src/ but needs the private header from it.
    target_include_directories(microfoam PRIVATE ${MCF_LZMA_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/src)
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
    endif()

    add_executable(v2_format_test tests/v2_format_test.c)
    target_link_libraries(v2_format_test PRIVATE microfoam)
    target_compile_options(v2_format_test PRIVATE ${MCF_WARNINGS})
    add_test(NAME v2_format_test COMMAND v2_format_test)

    add_executable(hal_concurrency_test tests/hal_concurrency_test.c)
    target_link_libraries(hal_concurrency_test PRIVATE microfoam)
    target_compile_options(hal_concurrency_test PRIVATE ${MCF_WARNINGS})
    add_test(NAME hal_concurrency_test COMMAND hal_concurrency_test)

    add_executable(microfoam_tests tests/test_microfoam.c)
    target_link_libraries(microfoam_tests PRIVATE microfoam)
    target_compile_options(microfoam_tests PRIVATE ${MCF_WARNINGS})
    add_test(NAME microfoam_tests COMMAND microfoam_tests)

    # Cross-implementation test: a patch produced by the Python host tool is
    # applied by the C library. A library verified only against its own encoder
    # proves nothing about the format, so this is the check that matters most.
    find_package(Python3 COMPONENTS Interpreter)
    if(Python3_Interpreter_FOUND)
        add_executable(cross_test tests/cross_test.c)
        target_link_libraries(cross_test PRIVATE microfoam)
        target_compile_options(cross_test PRIVATE ${MCF_WARNINGS})

        add_test(NAME host_selftest
                 COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/host/selftest.py)
        add_test(NAME cross_test
                 COMMAND ${CMAKE_COMMAND}
                         -DOLD=${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/old.bin
                         -DNEW=${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/new.bin
                         -DKEY=${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/key.priv
                         -DMCF=$<TARGET_FILE:cross_test>
                         -DPY=${Python3_EXECUTABLE}
                         -DTOOL=${CMAKE_CURRENT_SOURCE_DIR}/host/microfoam.py
                         -DWORK=${CMAKE_CURRENT_BINARY_DIR}/cross
                         -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/cross_test.cmake)
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
