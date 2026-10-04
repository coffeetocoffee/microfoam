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
            --nonce-prefix-ack-reuse
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
# Re-signed-but-invalid variants the C test uses. Each is structurally valid,
# carries a matching payload CRC and a valid signature, and fails exactly one
# downstream binding: the AAD record index, the nonce derivation, the AEAD tag,
# the ciphertext, or the key id. mfp2_fixtures.py --self-check proves every one
# parses and verifies before the host verifier rejects it, so none of them can
# silently degrade into a parse failure and pass for the wrong reason.
execute_process(
    COMMAND "${PY}" "${CMAKE_CURRENT_LIST_DIR}/../tests/mfp2_fixtures.py"
            --patch "${WORK}/valid.mfp2" --pub "${WORK}/public.key"
            --key "${WORK}/symmetric.key" --old "${OLD}"
            --signing-key "${WORK}/signing.key"
            --out-reordered "${WORK}/reordered.mfp2"
            --out-wrong-nonce "${WORK}/wrong_nonce.mfp2"
            --out-tag-tamper "${WORK}/tag_tamper.mfp2"
            --out-ct-tamper "${WORK}/ct_tamper.mfp2"
            --out-bad-key-id "${WORK}/bad_key_id.mfp2"
            --out-duplicated "${WORK}/duplicated.mfp2"
            --self-check
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "MFP2 variant fixture generation failed:\n${out}\n${err}")
endif()
# A second fixture over a small image (512-byte base, 128-byte target). The
# device's decode window is min(record_size, new_size), clamped to the image, so
# the producer must cap its framing at the image; a patch framed at the full
# record size is rejected at site 17 on the device. The C test's small-image
# case consumes this, and deleting the producer's cap regenerates the fixture
# uncapped so that case fails - the check is falsifiable, not merely green.
execute_process(
    COMMAND "${PY}" -c "from pathlib import Path; d=Path(r'${WORK}'); d.joinpath('small_old.bin').write_bytes(bytes((i*7+3)&0xFF for i in range(512))); d.joinpath('small_new.bin').write_bytes(bytes((i*5+11)&0xFF for i in range(128)))"
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "small-image fixture generation failed:\n${out}\n${err}")
endif()
execute_process(
    COMMAND "${PY}" "${TOOL}" make --v2
            --old "${WORK}/small_old.bin" --new "${WORK}/small_new.bin" --out "${WORK}/small.mfp2"
            --product 0x1234 --version 0x00020000 --old-version 0x00010000
            --signing-key "${WORK}/signing.key" --key "${WORK}/symmetric.key"
            --key-id 00112233445566778899aabbccddeeff
            --nonce-prefix 102132435465768798a9bacbdcedfe0f
            --nonce-prefix-ack-reuse
            --record-log2 8
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "small-image MFP2 fixture generation failed:\n${out}\n${err}")
endif()
execute_process(COMMAND "${MCF}" "${WORK}/valid.mfp2" "${OLD}" "${NEW}" "${WORK}/public.key" "${WORK}/symmetric.key"
                "${WORK}/reordered.mfp2" "${WORK}/wrong_nonce.mfp2"
                "${WORK}/tag_tamper.mfp2" "${WORK}/ct_tamper.mfp2" "${WORK}/bad_key_id.mfp2"
                "${WORK}/duplicated.mfp2"
                "${WORK}/small.mfp2" "${WORK}/small_old.bin" "${WORK}/small_new.bin"
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "MFP2 host-to-session integration failed:\n${out}\n${err}")
endif()
message(STATUS "${out}")
