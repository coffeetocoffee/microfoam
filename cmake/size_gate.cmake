# SPDX-License-Identifier: MIT
#
# Size regression gate.
#
# Compiles every library source for one Cortex core with arm-none-eabi-gcc and
# compares the resulting .text total against a committed baseline. The gate is
# a ceiling, not an equality: shrinking is always allowed, growing past the
# recorded figure fails until the baseline is deliberately updated in the same
# commit that caused the growth.
#
# This exists because CI previously printed arm-none-eabi-size output into the
# job summary and compared it with nothing, so a code-size regression could
# land unnoticed. The baseline file is the record; the summary is just a
# report.
#
# Usage:
#   cmake -DCORE=cortex-m0 -DCC=<gcc> -DSRC=<repo> -DBASELINE=<file> \
#         -DWORK=<dir> -P cmake/size_gate.cmake

foreach(v CORE CC SRC BASELINE WORK)
    if(NOT DEFINED ${v})
        message(FATAL_ERROR "size_gate.cmake requires -D${v}=...")
    endif()
endforeach()

file(MAKE_DIRECTORY "${WORK}")

# A CMake list, not a space-joined string: the repository path may contain
# spaces (this one does), and separate_arguments would split an -I flag in two.
set(FLAG_LIST
    "-mcpu=${CORE}" -mthumb -std=c99 -Os -ffunction-sections -fdata-sections
    -Wall -Wextra -Werror -Wconversion -Wsign-conversion -Wshadow -Wcast-qual
    "-I${SRC}/include" "-I${SRC}/src")

file(GLOB SOURCES "${SRC}/src/*.c")
set(OBJECTS "")

foreach(src ${SOURCES})
    get_filename_component(name "${src}" NAME_WE)

    # The libsodium adapter needs a host crypto library and the LZMA codec has
    # its own SDK include path; both are excluded from the bare-metal core
    # compile by the CI workflow for the same reason. The LZMA codec's size is
    # reported separately there.
    if(name STREQUAL "mcf_sodium" OR name STREQUAL "mcf_lzma")
        continue()
    endif()

    set(obj "${WORK}/${name}.o")
    execute_process(
        COMMAND "${CC}" ${FLAG_LIST} -c "${src}" -o "${obj}"
        RESULT_VARIABLE rc
        OUTPUT_VARIABLE out
        ERROR_VARIABLE  err)
    if(NOT rc EQUAL 0)
        message(FATAL_ERROR "compile failed for ${src} (${CORE}):\n${out}\n${err}")
    endif()
    list(APPEND OBJECTS "${obj}")
endforeach()

# arm-none-eabi-size prints a header and one row per object; the text column is
# the third field. Summing in CMake keeps the gate independent of host shell
# tools, which is the mistake the old summary step made by relying on bash.
execute_process(
    COMMAND arm-none-eabi-size ${OBJECTS}
    RESULT_VARIABLE rc
    OUTPUT_VARIABLE size_out
    ERROR_VARIABLE  size_err)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "arm-none-eabi-size failed: ${size_err}")
endif()

string(REPLACE "\n" ";" size_lines "${size_out}")
set(text_total 0)
set(data_total 0)
set(ram_total 0)
set(rows 0)

foreach(line ${size_lines})
    if(line MATCHES "^[ \t]*([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+(.*)$")
        if(NOT CMAKE_MATCH_5 STREQUAL "file(s)")
            math(EXPR text_total "${text_total} + ${CMAKE_MATCH_1}")
            math(EXPR data_total "${data_total} + ${CMAKE_MATCH_2}")
            math(EXPR ram_total  "${ram_total} + ${CMAKE_MATCH_3}")
            math(EXPR rows "${rows} + 1")
        endif()
    endif()
endforeach()

if(rows EQUAL 0)
    message(FATAL_ERROR "no size rows parsed from arm-none-eabi-size output:\n${size_out}")
endif()

# .data is initialised and lives in RAM as well as flash, so it is counted
# against RAM. The README claims 0 B of initialised data for the device build;
# this asserts that claim per target rather than trusting it.
math(EXPR static_ram "${data_total} + ${ram_total}")

file(STRINGS "${BASELINE}" baseline_lines)
set(baseline_text -1)
foreach(line ${baseline_lines})
    if(line MATCHES "^${CORE}[ \t]+([0-9]+)")
        set(baseline_text ${CMAKE_MATCH_1})
    endif()
endforeach()

if(baseline_text LESS 0)
    message(FATAL_ERROR "no baseline entry for ${CORE} in ${BASELINE}")
endif()

message(STATUS "${CORE}: text ${text_total} B (baseline ${baseline_text} B), static RAM ${static_ram} B, ${rows} objects")

if(text_total GREATER baseline_text)
    message(FATAL_ERROR
        "code size regression on ${CORE}: ${text_total} B exceeds the baseline of "
        "${baseline_text} B by ${text_total} - ${baseline_text} B. If the growth is "
        "intended, raise the ${CORE} line in ${BASELINE} in this commit.")
endif()

if(NOT static_ram EQUAL 0)
    message(FATAL_ERROR
        "static RAM regression on ${CORE}: ${static_ram} B of .data/.bss in a device "
        "build. The library keeps all tables const; anything else belongs in the "
        "caller's storage.")
endif()

message(STATUS "size gate passed for ${CORE}")
