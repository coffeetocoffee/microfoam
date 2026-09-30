# SPDX-License-Identifier: MIT
# Generate an independently signed/encrypted MFP2 patch, then apply and tamper-test it in C.
if(NOT DEFINED MCF OR NOT DEFINED WORK OR NOT DEFINED PY OR NOT DEFINED TOOL)
    message(FATAL_ERROR "mfp2_boundary_test.cmake requires MCF, WORK, PY, and TOOL")
endif()
file(MAKE_DIRECTORY "${WORK}")
execute_process(
    COMMAND "${PY}" -c "from pathlib import Path; from nacl.signing import SigningKey; d=Path(r'${WORK}'); s=bytes(range(32)); d.joinpath('signing.key').write_bytes(s); d.joinpath('public.key').write_bytes(bytes(SigningKey(s).verify_key)); d.joinpath('symmetric.key').write_bytes(bytes(range(32,64)))"
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "MFP2 key fixture generation failed:\n${out}\n${err}")
endif()
execute_process(
    COMMAND "${PY}" "${TOOL}" make --v2
            --old "${OLD}" --new "${NEW}" --out "${WORK}/valid.mfp2"
            --product 0x1234 --version 0x00020000 --old-version 0x00010000
            --signing-key "${WORK}/signing.key" --key "${WORK}/symmetric.key"
            --key-id 00112233445566778899aabbccddeeff
            --nonce-prefix 102132435465768798a9bacbdcedfe0f
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "MFP2 fixture generation failed:\n${out}\n${err}")
endif()
execute_process(COMMAND "${MCF}" "${WORK}/valid.mfp2" "${OLD}" "${NEW}" "${WORK}/public.key" "${WORK}/symmetric.key"
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "MFP2 host-to-session integration failed:\n${out}\n${err}")
endif()
message(STATUS "${out}")
