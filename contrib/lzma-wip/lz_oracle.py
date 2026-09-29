#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Minimum input prefix length needed per output byte, from liblzma.

**What this measures, and what it does not.** For each output length k it finds the
shortest input prefix from which liblzma yields k bytes without error. That is a
lower bound on the input required, not a measurement of what a streaming
decoder *reads*.

A streaming range decoder normalises whenever `range` drops below 2^24 and pulls
in a byte whether or not the current symbol needs it, so it reads ahead. liblzma
does the same; it is simply not observable through this interface. Comparing a
decoder's read position against these numbers therefore shows a gap that is
expected read-ahead, not a desync - an earlier version of this file was wrong
about exactly that and the mistake cost a whole round of debugging.

It remains useful for one thing: the value at k is an exact lower bound, so a
decoder that has read *fewer* bytes than the bound by k is definitely behind.

Writes consume_<vector>.txt: "<output_index> <min_input_bytes>" per line.
"""

import lzma
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", ".."))


def consumed_for(data, filt, k):
    """Shortest input prefix from which liblzma yields k output bytes."""
    lo, hi = 0, len(data)
    while lo < hi:
        mid = (lo + hi) // 2
        try:
            d = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filt)
            out = d.decompress(data[:mid], max_length=k)
            if len(out) >= k:
                hi = mid
            else:
                lo = mid + 1
        except lzma.LZMAError:
            lo = mid + 1
    return lo


def main():
    vector = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    upto = int(sys.argv[2]) if len(sys.argv) > 2 else 90

    path = os.path.join(REPO, "host", "lzma_vectors.bin")
    blob = open(path, "rb").read()
    count = struct.unpack_from("<I", blob, 0)[0]
    off = 4
    for i in range(count):
        pl, dl, bl = struct.unpack_from("<III", blob, off)
        off += 12
        props = blob[off:off + pl]
        data = blob[off + pl:off + pl + dl]
        plain = blob[off + pl + dl:off + pl + dl + bl]
        off += pl + dl + bl
        if i != vector:
            continue

        v = props[0]
        lc, lp, pb = v % 9, (v // 9) % 5, v // 45
        dsize = struct.unpack_from("<I", props, 1)[0]
        filt = [{"id": lzma.FILTER_LZMA1, "lc": lc, "lp": lp, "pb": pb,
                 "dict_size": dsize}]

        rows = []
        for k in range(1, upto + 1):
            c = consumed_for(data, filt, k)
            rows.append("%d %d" % (k, c))
        out = os.path.join(os.environ.get("TEMP", "."), "consume_%d.txt" % vector)
        with open(out, "w") as f:
            f.write("\n".join(rows))
        print("v%d: wrote %d rows to %s" % (vector, len(rows), out))
        for k in (1, 2, 5, 10, 32, 64, 75, 76):
            if k <= len(rows):
                print("  after %3d outputs: %d input bytes" % (k, int(rows[k - 1].split()[1])))
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
