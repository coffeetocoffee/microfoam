# SPDX-License-Identifier: MIT
#
# Drives the cross-implementation test: the Python host tool produces a patch
# from the fixtures, the C library applies it, and the result is compared with
# the target image. Run by ctest via the `cross_test` test.
#
# CODEC selects the codec the host tool is asked to produce: lz4 (default) or
# lzma. The LZMA variant is only registered when the library was built with
# MCF_ENABLE_LZMA=ON, because a default build correctly rejects LZMA patches.

if(DEFINED ENV{DST} OR NOT DEFINED MCF)
    message(FATAL_ERROR "cross_test.cmake must be invoked with -DMCF=<path to cross_test>")
endif()

if(NOT DEFINED CODEC)
    set(CODEC lz4)
endif()

file(MAKE_DIRECTORY "${WORK}")

# 1. Unsigned patch: the C library must reconstruct the target exactly.
execute_process(
    COMMAND "${PY}" "${TOOL}" make
            --old "${OLD}" --new "${NEW}" --out "${WORK}/patch-${CODEC}.bin"
            --product 0x1234 --version 0x00020000 --old-version 0x00010000
            --codec "${CODEC}"
    RESULT_VARIABLE rc
    OUTPUT_VARIABLE out
    ERROR_VARIABLE  err)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "host tool make (${CODEC}) failed:\n${out}\n${err}")
endif()

execute_process(
    COMMAND "${MCF}" "${OLD}" "${NEW}" "${WORK}/patch-${CODEC}.bin"
    RESULT_VARIABLE rc
    OUTPUT_VARIABLE out
    ERROR_VARIABLE  err)
message(STATUS "${CODEC} unsigned: ${out}")
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "cross test (${CODEC}) failed:\n${out}\n${err}")
endif()

# 2. Signed patch with no verifier configured: the device must fail closed
#    rather than accept an unverified image.
if(EXISTS "${KEY}")
    execute_process(
        COMMAND "${PY}" "${TOOL}" make
                --old "${OLD}" --new "${NEW}" --out "${WORK}/signed-${CODEC}.bin"
                --product 0x1234 --version 0x00020000 --old-version 0x00010000
                --codec "${CODEC}"
                --key "${KEY}"
        RESULT_VARIABLE rc
        OUTPUT_QUIET
        ERROR_VARIABLE  err)
    if(rc EQUAL 0)
        execute_process(
            COMMAND "${MCF}" "${OLD}" "${NEW}" "${WORK}/signed-${CODEC}.bin"
            RESULT_VARIABLE rc
            OUTPUT_VARIABLE out
            ERROR_VARIABLE  err)
        message(STATUS "${CODEC} signed: ${out}")
        if(rc EQUAL 0)
            message(FATAL_ERROR
                "a signed patch was accepted with no verifier configured; "
                "the library must fail closed")
        endif()
    endif()
endif()
