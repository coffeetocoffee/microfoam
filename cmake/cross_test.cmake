# SPDX-License-Identifier: MIT
#
# Drives the cross-implementation test: the Python host tool produces a patch
# from the fixtures, the C library applies it, and the result is compared with
# the target image. Run by ctest via the `cross_test` test.

if(DEFINED ENV{DST} OR NOT DEFINED MCF)
    message(FATAL_ERROR "cross_test.cmake must be invoked with -DMCF=<path to cross_test>")
endif()

file(MAKE_DIRECTORY "${WORK}")

# 1. Unsigned patch: the C library must reconstruct the target exactly.
execute_process(
    COMMAND "${PY}" "${TOOL}" make
            --old "${OLD}" --new "${NEW}" --out "${WORK}/patch.bin"
            --product 0x1234 --version 0x00020000 --old-version 0x00010000
    RESULT_VARIABLE rc
    OUTPUT_VARIABLE out
    ERROR_VARIABLE  err)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "host tool make failed:\n${out}\n${err}")
endif()

execute_process(
    COMMAND "${MCF}" "${OLD}" "${NEW}" "${WORK}/patch.bin"
    RESULT_VARIABLE rc
    OUTPUT_VARIABLE out
    ERROR_VARIABLE  err)
message(STATUS "unsigned: ${out}")
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "cross test failed:\n${out}\n${err}")
endif()

# 2. Signed patch with no verifier configured: the device must fail closed
#    rather than accept an unverified image.
if(EXISTS "${KEY}")
    execute_process(
        COMMAND "${PY}" "${TOOL}" make
                --old "${OLD}" --new "${NEW}" --out "${WORK}/signed.bin"
                --product 0x1234 --version 0x00020000 --old-version 0x00010000
                --key "${KEY}"
        RESULT_VARIABLE rc
        OUTPUT_QUIET
        ERROR_VARIABLE  err)
    if(rc EQUAL 0)
        execute_process(
            COMMAND "${MCF}" "${OLD}" "${NEW}" "${WORK}/signed.bin"
            RESULT_VARIABLE rc
            OUTPUT_VARIABLE out
            ERROR_VARIABLE  err)
        message(STATUS "signed: ${out}")
        if(rc EQUAL 0)
            message(FATAL_ERROR
                "a signed patch was accepted with no verifier configured; "
                "the library must fail closed")
        endif()
    endif()
endif()
