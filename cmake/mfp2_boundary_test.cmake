# SPDX-License-Identifier: MIT
# Generate an independently signed/encrypted MFP2 patch, then apply and
# tamper-test it in C. Also proves the host verifier accepts the valid patch
# and rejects the structurally-invalid variants the C test consumes.
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
# Small records so the fixture spans many records; the reorder and truncation
# tamper cases need at least two.
execute_process(
    COMMAND "${PY}" "${TOOL}" make --v2
            --old "${OLD}" --new "${NEW}" --out "${WORK}/valid.mfp2"
            --product 0x1234 --version 0x00020000 --old-version 0x00010000
            --signing-key "${WORK}/signing.key" --key "${WORK}/symmetric.key"
            --key-id 00112233445566778899aabbccddeeff
            --nonce-prefix 102132435465768798a9bacbdcedfe0f
            --record-log2 8
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "MFP2 fixture generation failed:\n${out}\n${err}")
endif()
# Host-side gate over the exact bytes the C session is about to consume:
# signature/structure verified, decrypt/apply must reconstruct new.bin.
execute_process(
    COMMAND "${PY}" "${TOOL}" verify "${WORK}/valid.mfp2" --pub "${WORK}/public.key"
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "MFP2 host verify rejected the valid fixture:\n${out}\n${err}")
endif()
execute_process(
    COMMAND "${PY}" "${TOOL}" apply --old "${OLD}" --patch "${WORK}/valid.mfp2"
            --out "${WORK}/applied.bin" --pub "${WORK}/public.key" --key "${WORK}/symmetric.key"
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "MFP2 host apply failed:\n${out}\n${err}")
endif()
execute_process(COMMAND "${CMAKE_COMMAND}" -E compare_files "${WORK}/applied.bin" "${NEW}"
    RESULT_VARIABLE rc)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "MFP2 host apply output differs from new.bin")
endif()
# Signed-but-invalid variants the C test uses: reordered records, mismatched
# nonce prefix. mfp2_fixtures.py --self-check proves the host verifier
# rejects both before handing them to the device path.
execute_process(
    COMMAND "${PY}" "${CMAKE_CURRENT_LIST_DIR}/../tests/mfp2_fixtures.py"
            --patch "${WORK}/valid.mfp2" --pub "${WORK}/public.key"
            --key "${WORK}/symmetric.key" --old "${OLD}"
            --signing-key "${WORK}/signing.key"
            --out-reordered "${WORK}/reordered.mfp2"
            --out-wrong-nonce "${WORK}/wrong_nonce.mfp2"
            --self-check
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "MFP2 variant fixture generation failed:\n${out}\n${err}")
endif()
execute_process(COMMAND "${MCF}" "${WORK}/valid.mfp2" "${OLD}" "${NEW}" "${WORK}/public.key" "${WORK}/symmetric.key"
                "${WORK}/reordered.mfp2" "${WORK}/wrong_nonce.mfp2"
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "MFP2 host-to-session integration failed:\n${out}\n${err}")
endif()
message(STATUS "${out}")
