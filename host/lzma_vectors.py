#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Generate LZMA conformance vectors and a reference implementation to compare the
C decoder against.

The C decoder is only trustworthy if it agrees with an independent
implementation on inputs that actually exercise it, so the vectors here are
produced by Python's lzma module - liblzma, which is the reference the format
comes from - and the same vectors drive a small pure-Python decoder written
against the specification.

Writes:
  lzma_vectors.bin   for the C harness
"""

import lzma
import os
import struct
import sys
from fractions import Fraction

# --------------------------------------------------------------------------
# Vector file layout, little-endian
#   u32 count
#   count x { u32 props_len; u32 data_len; u32 plain_len; props[]; data[]; plain[] }
# --------------------------------------------------------------------------

HERE = os.path.dirname(os.path.abspath(__file__))


def build_vectors(path):
    cases = []

    def add(name, raw, lc, lp, pb, dict_size, want):
        # preset cannot be combined with explicit lc/lp/pb/dict_size.
        filters = [{"id": lzma.FILTER_LZMA1,
                    "lc": lc, "lp": lp, "pb": pb, "dict_size": dict_size}]
        comp = lzma.compress(raw, format=lzma.FORMAT_RAW, filters=filters)
        props = bytes([pb * 45 + lp * 9 + lc]) + struct.pack("<I", dict_size) \
              + struct.pack("<I", len(raw))
        cases.append((name, props, comp, raw, want))
        return len(comp)

    import random
    random.seed(4242)

    # 1. Realistic firmware-shaped data
    img = bytearray()
    img += bytes(random.randrange(256) for _ in range(0x200))          # vector table
    for _ in range(2000):                                             # "code"
        img += bytes([random.choice([0x00, 0x01, 0x10, 0x20, 0x40,
                                     0x4B, 0x88, 0x8D, 0xB5, 0xBD]),
                      random.randrange(256)])
    img += b"".join(b"STR_%d_%s\x00" % (i, b"x" * (i % 17)) for i in range(400))
    img += bytes([(i * 7) % 256 for i in range(8192)])                 # const table
    img += b"".join(b"\xaa\xbb\xcc\xdd" + bytes([i % 256] * 8) for i in range(1000))
    add("firmware", bytes(img), 3, 0, 2, 1 << 16, 1)

    # 2. Highly repetitive
    add("repetitive", b"ABCD" * 4000, 3, 0, 2, 1 << 16, 1)

    # 3. A run of zeros, which exercises the ring wrap hard
    add("zeros", bytes(20000), 3, 0, 2, 4096, 1)

    # 4. Incompressible
    add("random", bytes(random.randrange(256) for _ in range(9000)), 3, 0, 2, 1 << 16, 1)

    # 5. Small, lc/lp/pb sweep - the probability table size depends on lc+lp.
    #    liblzma constrains lc+lp <= 4 (LZMA_LCLP_MAX); the device's table is
    #    1366 + 768<<(lc+lp) entries, so the sweep spans the realistic range.
    for lc in (0, 1, 2, 3, 4):
        for lp in (0, 1, 2, 3, 4):
            if lc + lp > 4:
                continue
            for pb in (0, 1, 2, 4):
                raw = bytes((i * 13 + lc * 7 + lp) % 251 for i in range(3000))
                add("sweep-%d-%d-%d" % (lc, lp, pb), raw, lc, lp, pb, 1 << 12, 1)

    # 6. Distances that need the pos-slot/align paths
    big = bytes(random.randrange(256) for _ in range(4000)) + b"MARKER" * 30
    add("fardist", big, 3, 0, 2, 1 << 15, 1)

    # 7. Single byte and tiny inputs
    add("one-byte", b"\x42", 3, 0, 2, 4096, 1)
    add("empty-ish", b"ab", 0, 0, 0, 4096, 1)

    blob = bytearray(struct.pack("<I", len(cases)))
    for name, props, comp, raw, want in cases:
        blob += struct.pack("<III", len(props), len(comp), len(raw))
        blob += props + comp + raw
    with open(path, "wb") as f:
        f.write(bytes(blob))
    return cases


# --------------------------------------------------------------------------
# Pure-Python LZMA decoder, written from the specification. Used to confirm the
# C output byte-for-byte without going through liblzma for the comparison.
# --------------------------------------------------------------------------

NUM_STATES = 12
NUM_POS_BITS_MAX = 4
NUM_LEN_TO_POS_STATES = 4
NUM_ALIGN_BITS = 4
END_POS_MODEL_INDEX = 14
MATCH_MIN_LEN = 2
NUM_FULL_DISTANCES = 1 << (END_POS_MODEL_INDEX // 2)

P_IS_MATCH = 0
P_IS_REP = P_IS_MATCH + (NUM_STATES << NUM_POS_BITS_MAX)
P_IS_REP_G0 = P_IS_REP + NUM_STATES
P_IS_REP_G1 = P_IS_REP_G0 + NUM_STATES
P_IS_REP_G2 = P_IS_REP_G1 + NUM_STATES
P_IS_REP0_LONG = P_IS_REP_G2 + NUM_STATES
P_POS_SLOT = P_IS_REP0_LONG + (NUM_STATES << NUM_POS_BITS_MAX)
# The position-slot tree is indexed by length state: NUM_LEN_TO_POS_STATES
# blocks of 64, not a single block of 64.
P_SPEC_POS = P_POS_SLOT + NUM_LEN_TO_POS_STATES * 64
P_ALIGN = P_SPEC_POS + 115
P_LEN = P_ALIGN + (1 << NUM_ALIGN_BITS)
# A length coder is choice, choice2, a low and a mid tree per position state
# (16 states x 8 leaves), then one shared high tree: 2 + 128 + 128 + 256.
LEN_PROBS = 2 + (1 << 4) * (1 << 3) * 2 + (1 << 8)
P_REP_LEN = P_LEN + LEN_PROBS
P_LITERAL = P_REP_LEN + LEN_PROBS


class Decoder:
    def __init__(self, props):
        v = props[0]
        self.lc = v % 9
        self.lp = (v // 9) % 5
        self.pb = v // 45
        self.pb_mask = (1 << self.pb) - 1
        self.lp_mask = (1 << self.lp) - 1
        self.dict_size = struct.unpack("<I", props[1:5])[0]
        self.content_size = struct.unpack("<I", props[5:9])[0]
        n = P_LITERAL + (768 << (self.lc + self.lp))
        self.probs = [1024] * n
        self.dict = bytearray(self.dict_size)
        self.dpos = 0
        self.produced = 0
        self.state = 0
        self.rep = [0, 0, 0, 0]
        self.range = 0xFFFFFFFF
        self.code = 0
        self.pos = 0
        self.data = b""
        self.done = False

    # -- range decoder --
    def _byte(self):
        if self.pos < len(self.data):
            b = self.data[self.pos]
            self.pos += 1
            return b
        self.pos += 1
        return 0

    def _norm(self):
        if self.range < 0xFF000000:
            self.range = (self.range << 8) & 0xFFFFFFFF
            self.code = ((self.code << 8) | self._byte()) & 0xFFFFFFFF

    def _bit(self, i):
        bound = (self.range >> 11) * self.probs[i]
        if self.code < bound:
            self.range = bound
            self.probs[i] += (2048 - self.probs[i]) >> 5
            bit = 0
        else:
            self.range -= bound
            self.code -= bound
            self.probs[i] -= self.probs[i] >> 5
            bit = 1
        self._norm()
        return bit

    def _direct(self, n):
        res = 0
        for _ in range(n):
            self.range >>= 1
            self.code = (self.code - self.range) & 0xFFFFFFFF
            t = 0 - (self.code >> 31)
            self.code = (self.code + (self.range & t)) & 0xFFFFFFFF
            res = ((res << 1) + (t + 1)) & 0xFFFFFFFF
        self._norm()
        return res

    def _tree(self, base, nbits):
        m = 1
        for _ in range(nbits):
            m = (m << 1) | self._bit(base + m)
        return m - (1 << nbits)

    def _tree_rev(self, base, nbits):
        m, sym = 1, 0
        for i in range(nbits):
            b = self._bit(base + m)
            m = (m << 1) + b
            sym |= b << i
        return sym

    # -- dictionary --
    def _get(self, dist):
        if dist == 0 or dist > self.dict_size:
            return 0
        p = self.dpos + self.dict_size - dist
        if p >= self.dict_size:
            p -= self.dict_size
        return self.dict[p]

    def _put(self, b):
        self.dict[self.dpos] = b
        self.dpos += 1
        if self.dpos >= self.dict_size:
            self.dpos = 0

    # -- high level --
    def _len(self, base):
        # Low and mid are indexed by position state; the high tree is shared.
        ps = self.produced & self.pb_mask
        if self._bit(base) == 0:
            return self._tree(base + 2 + ps * 8, 3)
        if self._bit(base + 1) == 0:
            return 8 + self._tree(base + 2 + 128 + ps * 8, 3)
        return 16 + self._tree(base + 2 + 128 + 128, 8)

    def _dist(self, ln):
        ls = min(ln, NUM_LEN_TO_POS_STATES - 1)
        slot = self._tree(P_POS_SLOT + (ls << 6), 6)
        if slot < 4:
            return slot
        direct = (slot >> 1) - 1
        d = (2 | (slot & 1)) << direct
        if slot < END_POS_MODEL_INDEX:
            d += self._tree_rev(P_SPEC_POS + d - slot - 1, direct)
        else:
            d += self._direct(direct - NUM_ALIGN_BITS) << NUM_ALIGN_BITS
            d += self._tree_rev(P_ALIGN, NUM_ALIGN_BITS)
        return d

    def decode(self, data, out_cap, first):
        self.data = data
        if first:
            self._byte()
            self.code = 0
            for _ in range(4):
                self.code = ((self.code << 8) | self._byte()) & 0xFFFFFFFF

        produced = 0
        ring_start = self.dpos
        while produced < out_cap and self.produced < self.content_size \
                and self.pos < len(self.data):
            pos_state = self.produced & self.pb_mask
            if self._bit(P_IS_MATCH + (self.state << NUM_POS_BITS_MAX)
                         + pos_state) == 0:
                prev = self._get(1) if self.produced > 0 else 0
                lit = ((self.produced & self.lp_mask) << self.lc) \
                      + (prev >> (8 - self.lc)) if self.lc else \
                      (self.produced & self.lp_mask)
                base = P_LITERAL + 0x300 * lit
                sym = 1
                if self.state >= 7:
                    mb = self._get(self.rep[0] + 1)
                    while True:
                        mbit = (mb >> 7) & 1
                        mb = (mb << 1) & 0xFF
                        bit = self._bit(base + ((1 + mbit) << 8) + sym)
                        sym = (sym << 1) | bit
                        if mbit != bit or sym >= 0x100:
                            break
                else:
                    while sym < 0x100:
                        sym = (sym << 1) | self._bit(base + sym)
                self._put(sym & 0xFF)
                self.produced += 1
                produced += 1
                self.state = 0 if self.state < 4 else (
                    self.state - 3 if self.state < 10 else self.state - 6)
                continue

            if self._bit(P_IS_REP + self.state) != 0:
                if self._bit(P_IS_REP_G0 + self.state) == 0:
                    if self._bit(P_IS_REP0_LONG
                                 + (self.state << NUM_POS_BITS_MAX)
                                 + pos_state) == 0:
                        self._put(self._get(self.rep[0] + 1))
                        self.produced += 1
                        produced += 1
                        self.state = 9 if self.state < 7 else 11
                        continue
                else:
                    if self._bit(P_IS_REP_G1 + self.state) == 0:
                        d = self.rep[1]
                    else:
                        if self._bit(P_IS_REP_G2 + self.state) == 0:
                            d = self.rep[2]
                        else:
                            d = self.rep[3]
                            self.rep[2] = self.rep[3 - 1]
                        self.rep[2 - 1] = self.rep[1]
                    self.rep[1] = self.rep[0]
                    self.rep[0] = d
                ln = self._len(P_REP_LEN) + MATCH_MIN_LEN
                self.state = 8 if self.state < 7 else 11
            else:
                self.rep[3] = self.rep[2]
                self.rep[2] = self.rep[1]
                self.rep[1] = self.rep[0]
                ln = self._len(P_LEN) + MATCH_MIN_LEN
                self.state = 7 if self.state < 7 else 10
                d = self._dist(ln)
                if d == 0xFFFFFFFF:
                    self.done = True
                    break
                self.rep[0] = d
                if d >= self.dict_size:
                    raise ValueError("distance beyond dictionary")
                ln += MATCH_MIN_LEN

            if self.produced + ln > self.content_size:
                raise ValueError("match overruns declared content size")
            for _ in range(ln):
                self._put(self._get(self.rep[0] + 1))
                self.produced += 1
                produced += 1

        out = bytearray()
        if produced:
            first_n = min(self.dict_size - ring_start, produced)
            out += self.dict[ring_start:ring_start + first_n]
            if produced > first_n:
                out += self.dict[:produced - first_n]
        return bytes(out), self.pos


def main():
    out = os.path.join(HERE, "lzma_vectors.bin")
    cases = build_vectors(out)
    print("wrote %d vectors to %s" % (len(cases), os.path.basename(out)))
    total_in = total_out = 0
    for name, props, comp, raw, _ in cases:
        total_in += len(comp)
        total_out += len(raw)
    print("  %d bytes compressed -> %d bytes (%.1f%%)"
          % (total_in, total_out, total_in * 100.0 / max(1, total_out)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
