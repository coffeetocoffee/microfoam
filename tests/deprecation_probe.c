/* SPDX-License-Identifier: MIT */
/*
 * Microfoam - deprecation-diagnostic probe.
 *
 * Not a test suite, never linked into a build product, and not compiled by the
 * normal build. cmake/deprecation_probe.cmake compiles this file with the
 * configured toolchain at configure time and reads the diagnostics back out of
 * the compiler's own output, twice:
 *
 *   1. by default, asserting each MCF_DEPRECATED message in microfoam.h
 *      appears verbatim in the output, and
 *   2. with MCF_PROBE_SUPPRESSED defined, asserting the compile is clean and
 *      both diagnostics are gone (the MCF_NO_DEPRECATED promise).
 *
 * Why this file exists: the message is the only part of the deprecation
 * contract that nothing else can observe. The header compiles either way, so a
 * message that quietly stopped being emitted would leave every other gate
 * green while the promise in docs/architecture.md section 19.3 - that the
 * diagnostic names the migration path - stopped being true.
 *
 * The stubs below exist only so the probe links as a self-contained program
 * with no library dependency; the calls in main() are the observation. They do
 * not mock library behaviour and nothing depends on what they return.
 */

/* The default direction asserts the header's default behaviour, so an ambient
 * -DMCF_NO_DEPRECATED from the parent build's flags must not leak in and
 * silently satisfy it. The suppressed direction sets the macro deliberately,
 * without redefining it if the build already did. */
#if defined(MCF_PROBE_SUPPRESSED)
#  if !defined(MCF_NO_DEPRECATED)
#    define MCF_NO_DEPRECATED
#  endif
#else
#  undef MCF_NO_DEPRECATED
#endif

#if defined(_MSC_VER)
/* MSVC only reports C4996 at /W3 and above, and a try_compile project's
 * warning level is not ours to set from the parent. Raising the warning to
 * level 1 makes the diagnostic appear at any /W. The probe uses no CRT
 * functions, so no unrelated C4996 can fire. */
#  pragma warning(1:4996)
#endif

#include "microfoam.h"

mcf_status_t mcf_hal_register(const mcf_hal_t *hal)
{
    (void)hal;
    return MCF_OK;
}

mcf_status_t mcf_hal_set_static_workspace(const mcf_hal_t *hal, void *bytes,
                                          uint32_t size)
{
    (void)hal;
    (void)bytes;
    (void)size;
    return MCF_OK;
}

mcf_status_t mcf_codec_register(const mcf_codec_ops_t *ops)
{
    (void)ops;
    return MCF_OK;
}

int main(void)
{
    mcf_hal_t     hal = {0};
    unsigned char ws[16];
    mcf_codec_ops_t codec = {0};
    mcf_status_t  a;
    mcf_status_t  b;
    mcf_status_t  c;

    /* Each call is expected to draw one deprecation diagnostic carrying the
     * message declared in the header. */
    a = mcf_hal_register(&hal);
    b = mcf_hal_set_static_workspace(&hal, ws, (uint32_t)sizeof(ws));
    c = mcf_codec_register(&codec);
    return (a == MCF_OK && b == MCF_OK && c == MCF_OK) ? 0 : 1;
}
