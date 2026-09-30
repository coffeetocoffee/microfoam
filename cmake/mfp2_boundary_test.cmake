# SPDX-License-Identifier: MIT
# Generate an independently signed/encrypted MFP2 patch, then test the C boundary.
if(NOT DEFINED MCF OR NOT DEFINED WORK OR NOT DEFINED PY OR NOT DEFINED TOOL)
    message(FATAL_ERROR "mfp2_boundary_test.cmake requires MCF, WORK, PY, and TOOL")
endif()
file(MAKE_DIRECTORY "${WORK}")
execute_process(
    COMMAND "${PY}" "${TOOL}" make --v2
            --old "${OLD}" --new "${NEW}" --out "${WORK}/valid.mfp2"
            --product 0x1234 --version 0x00020000 --old-version 0x00010000
            --signing-key "${SIGNING_KEY}" --key "${SIGNING_KEY}"
            --key-id 00112233445566778899aabbccddeeff
            --nonce-prefix 102132435465768798a9bacbdcedfe0f
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "MFP2 fixture generation failed:\n${out}\n${err}")
endif()
execute_process(COMMAND "${MCF}" "${WORK}/valid.mfp2"
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "MFP2 host-to-parser boundary failed:\n${out}\n${err}")
endif()
message(STATUS "${out}")
