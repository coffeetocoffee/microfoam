# SPDX-License-Identifier: MIT
#
# Deprecation-diagnostic gate.
#
# The MCF_DEPRECATED messages in microfoam.h are the migration path a caller
# sees at the moment of the mistake. They are also the one part of the
# deprecation contract nothing else in the build can observe: the header
# compiles whether or not a message is emitted, so a message that quietly
# stopped being printed would leave every other gate green while the promise
# in docs/architecture.md section 19.3 - that the diagnostic names the
# replacement - stopped being true.
#
# This compiles tests/deprecation_probe.c with the configured toolchain, twice,
# at configure time:
#
#   direction 1 (default)              both messages must appear verbatim in
#                                      the compiler's own output
#   direction 2 (MCF_PROBE_SUPPRESSED) the compile must succeed and neither
#                                      message may appear (the MCF_NO_DEPRECATED
#                                      promise)
#
# Both directions are falsifiable, and three sabotages were run against this
# file when it was added:
#   * strip the message from the attribute in microfoam.h
#     (`deprecated` instead of `deprecated(msg)`)        -> direction 1 fails
#   * reword one message in the header only               -> direction 1 fails
#   * make MCF_NO_DEPRECATED emit the attribute again
#     (suppression broken)                                -> direction 2 fails
#
# The compiles are compile-only (CMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY),
# never linked, so a CMake-configured bare-metal cross build - which passes its
# own compiler check through a toolchain file but cannot link a host executable
# - runs this gate without a linker script. Direction 1 tolerates a failing
# compile on purpose - with -Werror in the parent's flags the diagnostic appears
# in the error text, which is all direction 1 reads - while direction 2
# requires a clean compile, because suppression that still warns is the defect
# it exists to catch.

if(NOT DEFINED MCF_DEPRECATION_PROBE_INCLUDED)
set(MCF_DEPRECATION_PROBE_INCLUDED 1)

get_filename_component(_mcf_probe_src
    "${CMAKE_CURRENT_LIST_DIR}/../tests/deprecation_probe.c" ABSOLUTE)
get_filename_component(_mcf_probe_inc
    "${CMAKE_CURRENT_LIST_DIR}/../include" ABSOLUTE)

# The two strings are duplicated from microfoam.h on purpose: the duplication
# is what turns "the message says what we promised" from prose into a check.
# Rewording a message requires updating this file in the same commit, and a
# mismatch fails the configure with the exact expected text in the error.
set(_mcf_msg_register
    "set cfg.hal in mcf_config_t instead (the HAL is per session)")
set(_mcf_msg_workspace
    "set cfg.workspace and cfg.workspace_size in mcf_config_t instead")

# Compile the probe once. Returns the try_compile result and the combined
# output (which carries the diagnostics) to the caller's scope.
function(mcf_deprecation_probe_compile tag define out_ok out_log)
    # Compile only, never link. This is set here, in the scope try_compile
    # reads it from, rather than passed through CMAKE_FLAGS: that route reaches
    # the child project too late and the link still runs (verified on MSVC
    # 19.44, where a link step appeared regardless). Compile-only is what lets
    # a bare-metal cross toolchain - which cannot link a host executable
    # without a linker script - run this gate too.
    set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
    set(_defs "")
    if(NOT "${define}" STREQUAL "")
        set(_defs "-DCOMPILE_DEFINITIONS=${define}")
    endif()
    try_compile(_ok
        "${CMAKE_BINARY_DIR}/deprecation-probe/${tag}"
        SOURCES "${_mcf_probe_src}"
        CMAKE_FLAGS
            "-DINCLUDE_DIRECTORIES=${_mcf_probe_inc}"
            ${_defs}
        OUTPUT_VARIABLE _log)
    set(${out_ok} ${_ok} PARENT_SCOPE)
    set(${out_log} "${_log}" PARENT_SCOPE)
endfunction()

# Compare on whitespace-free text: a diagnostic that wraps across lines (or is
# re-indented by a build tool) must still match the message it carries.
function(mcf_deprecation_probe_normalize text out)
    string(REGEX REPLACE "[ \t\r\n]+" "" _t "${text}")
    set(${out} "${_t}" PARENT_SCOPE)
endfunction()

# The try_compile result of direction 1 is deliberately unused: a parent
# configure with -Werror turns each diagnostic into an error, and the message
# this gate reads is in that error text just the same. Requiring a clean
# compile there would make the gate fail on a correct header.
mcf_deprecation_probe_compile(default "" probe_ok probe_log)
mcf_deprecation_probe_normalize("${probe_log}" probe_norm)
mcf_deprecation_probe_normalize("${_mcf_msg_register}" msg_register)
mcf_deprecation_probe_normalize("${_mcf_msg_workspace}" msg_workspace)

string(FIND "${probe_norm}" "${msg_register}" _at_register)
string(FIND "${probe_norm}" "${msg_workspace}" _at_workspace)

if(_at_register EQUAL -1 OR _at_workspace EQUAL -1)
    message(FATAL_ERROR
        "deprecation messages do not reach the compiler output.\n"
        "Expected mcf_hal_register() to emit:\n  ${_mcf_msg_register}\n"
        "and mcf_hal_set_static_workspace() to emit:\n  ${_mcf_msg_workspace}\n"
        "Compiling ${_mcf_probe_src} with the configured toolchain produced:\n"
        "${probe_log}\n"
        "If the message was reworded deliberately, update the expected strings "
        "in cmake/deprecation_probe.cmake in the same commit.")
endif()

mcf_deprecation_probe_compile(suppressed "-DMCF_PROBE_SUPPRESSED" sup_ok sup_log)
mcf_deprecation_probe_normalize("${sup_log}" sup_norm)

string(FIND "${sup_norm}" "${msg_register}" _sup_register)
string(FIND "${sup_norm}" "${msg_workspace}" _sup_workspace)

if(NOT sup_ok)
    message(FATAL_ERROR
        "MCF_NO_DEPRECATED build of ${_mcf_probe_src} failed; the suppression "
        "path must compile cleanly. Compiler output:\n${sup_log}")
endif()
if(NOT _sup_register EQUAL -1 OR NOT _sup_workspace EQUAL -1)
    message(FATAL_ERROR
        "MCF_NO_DEPRECATED did not suppress the deprecation diagnostics; a "
        "downstream tree mid-migration would still see them. Compiler "
        "output:\n${sup_log}")
endif()

message(STATUS
    "deprecation probe: both MCF_DEPRECATED messages reach the compiler, "
    "MCF_NO_DEPRECATED suppresses them")

endif() # MCF_DEPRECATION_PROBE_INCLUDED
