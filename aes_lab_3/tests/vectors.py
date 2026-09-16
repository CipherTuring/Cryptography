"""
Published AES constants and test vectors, used as an external oracle.

Exercise 2. Nothing in this file is imported by `aeslib`: these are the
values as printed in the standards, transcribed here so that the tests
can check the implementation against something it did not produce
itself. If a table were shared between the implementation and the test,
the test would only prove that the code agrees with itself.

Sources:

- FIPS PUB 197, "Advanced Encryption Standard": Figure 7 (S-box),
  Figure 14 (inverse S-box), Figure 11 (round constants),
  Appendix A (key expansion), Appendix B (cipher example) and
  Appendix C (one example per key size).
- NIST SP 800-38A, Appendix F.1, for the multi-block ECB examples.
- The Rijndael proposal, for the single-column MixColumns vectors.
"""

__all__ = [
    "FIPS197_SBOX",
    "FIPS197_INV_SBOX",
    "APPENDIX_B_PLAINTEXT",
    "APPENDIX_B_KEY",
    "APPENDIX_B_ROUND1_START",
    "APPENDIX_B_ROUND1_AFTER_SUB_BYTES",
    "APPENDIX_B_ROUND1_AFTER_SHIFT_ROWS",
    "APPENDIX_B_ROUND1_AFTER_MIX_COLUMNS",
    "APPENDIX_B_ROUND1_KEY",
    "MIX_COLUMNS_VECTORS",
    "APPENDIX_A_KEY_128",
    "APPENDIX_A_KEY_192",
    "APPENDIX_A_KEY_256",
    "APPENDIX_A_ROUND_KEYS_128",
    "APPENDIX_A_LAST_ROUND_KEY_192",
    "APPENDIX_A_LAST_ROUND_KEY_256",
    "FIPS197_ROUND_CONSTANTS",
    "APPENDIX_C_PLAINTEXT",
    "APPENDIX_C_VECTORS",
    "APPENDIX_B_CIPHERTEXT",
    "SP800_38A_PLAINTEXT",
    "SP800_38A_ECB_VECTORS",
]


# ---------------------------------------------------------------------------
# FIPS-197, Figure 7: the S-box, in the usual 16x16 layout. The byte
# 0xXY is substituted by the entry at row X, column Y.
# ---------------------------------------------------------------------------

FIPS197_SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)


# ---------------------------------------------------------------------------
# FIPS-197, Figure 14: the inverse S-box.
# ---------------------------------------------------------------------------

FIPS197_INV_SBOX = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
    0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
    0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
    0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
    0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
    0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
    0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
    0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
    0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
    0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
    0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
    0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
    0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
    0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
    0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
    0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)


# ---------------------------------------------------------------------------
# FIPS-197, Appendix B ("Cipher Example"): the round-by-round trace of a
# single AES-128 encryption. Only round 1 is transcribed here, which is
# enough to pin down SubBytes, ShiftRows and MixColumns individually: the
# output of each step is the input of the next, so the three values have
# to line up with one another as well as with the implementation.
# ---------------------------------------------------------------------------

APPENDIX_B_PLAINTEXT = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
APPENDIX_B_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")

# Round 1, as printed in the "Round Number 1" block of the appendix.
APPENDIX_B_ROUND1_START = bytes.fromhex("193de3bea0f4e22b9ac68d2ae9f84808")
APPENDIX_B_ROUND1_AFTER_SUB_BYTES = bytes.fromhex("d42711aee0bf98f1b8b45de51e415230")
APPENDIX_B_ROUND1_AFTER_SHIFT_ROWS = bytes.fromhex("d4bf5d30e0b452aeb84111f11e2798e5")
APPENDIX_B_ROUND1_AFTER_MIX_COLUMNS = bytes.fromhex("046681e5e0cb199a48f8d37a2806264c")
APPENDIX_B_ROUND1_KEY = bytes.fromhex("a0fafe17 88542cb1 23a33939 2a6c7605".replace(" ", ""))


# ---------------------------------------------------------------------------
# Single-column MixColumns vectors, the ones commonly quoted alongside
# the Rijndael proposal. Each pair is (input column, expected output).
# ---------------------------------------------------------------------------

MIX_COLUMNS_VECTORS = (
    ((0xDB, 0x13, 0x53, 0x45), (0x8E, 0x4D, 0xA1, 0xBC)),
    ((0xF2, 0x0A, 0x22, 0x5C), (0x9F, 0xDC, 0x58, 0x9D)),
    ((0x01, 0x01, 0x01, 0x01), (0x01, 0x01, 0x01, 0x01)),
    ((0xC6, 0xC6, 0xC6, 0xC6), (0xC6, 0xC6, 0xC6, 0xC6)),
    ((0xD4, 0xD4, 0xD4, 0xD5), (0xD5, 0xD5, 0xD7, 0xD6)),
    ((0x2D, 0x26, 0x31, 0x4C), (0x4D, 0x7E, 0xBD, 0xF8)),
)


# ---------------------------------------------------------------------------
# FIPS-197, Appendix A: key expansion examples. The three keys below are
# the ones the appendix expands, one per key size.
#
# For AES-128 the eleven round keys are transcribed in full (A.1). For
# AES-192 and AES-256 only the first and last round keys are listed: the
# first is the key itself and the last is the hardest value to get right,
# since an error anywhere in the schedule propagates to it. The middle of
# those two expansions is covered transitively by the Appendix C cipher
# vectors, which cannot match unless every round key is correct.
# ---------------------------------------------------------------------------

APPENDIX_A_KEY_128 = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
APPENDIX_A_KEY_192 = bytes.fromhex(
    "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
)
APPENDIX_A_KEY_256 = bytes.fromhex(
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
)

# A.1 -- the complete expansion for the 128-bit key, as round keys.
APPENDIX_A_ROUND_KEYS_128 = tuple(
    bytes.fromhex(value)
    for value in (
        "2b7e151628aed2a6abf7158809cf4f3c",
        "a0fafe1788542cb123a339392a6c7605",
        "f2c295f27a96b9435935807a7359f67f",
        "3d80477d4716fe3e1e237e446d7a883b",
        "ef44a541a8525b7fb671253bdb0bad00",
        "d4d1c6f87c839d87caf2b8bc11f915bc",
        "6d88a37a110b3efddbf98641ca0093fd",
        "4e54f70e5f5fc9f384a64fb24ea6dc4f",
        "ead27321b58dbad2312bf5607f8d292f",
        "ac7766f319fadc2128d12941575c006e",
        "d014f9a8c9ee2589e13f0cc8b6630ca6",
    )
)

# A.2 and A.3 -- the final round key of each expansion.
APPENDIX_A_LAST_ROUND_KEY_192 = bytes.fromhex("e98ba06f448c773c8ecc720401002202")
APPENDIX_A_LAST_ROUND_KEY_256 = bytes.fromhex("fe4890d1e6188d0b046df344706c631e")

# FIPS-197, Figure 11: the ten round constants used by the schedule.
FIPS197_ROUND_CONSTANTS = (
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
)


# ---------------------------------------------------------------------------
# FIPS-197, Appendix C: one worked example per key size. All three share
# the same plaintext and use a key that is simply the ascending byte
# sequence, so the only thing that changes between them is the key
# length, and with it the number of rounds.
# ---------------------------------------------------------------------------

APPENDIX_C_PLAINTEXT = bytes.fromhex("00112233445566778899aabbccddeeff")

# (key, expected ciphertext)
APPENDIX_C_VECTORS = (
    (
        bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
        bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"),
    ),
    (
        bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617"),
        bytes.fromhex("dda97ca4864cdfe06eaf70a0ec0d7191"),
    ),
    (
        bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        ),
        bytes.fromhex("8ea2b7ca516745bfeafc49904b496089"),
    ),
)

# FIPS-197, Appendix B: the ciphertext of the worked example whose first
# round is transcribed above.
APPENDIX_B_CIPHERTEXT = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")


# ---------------------------------------------------------------------------
# NIST SP 800-38A, Appendix F.1: the ECB examples. Four blocks per key
# size, which exercise the cipher over a multi-block buffer rather than a
# single block. The keys are the ones of FIPS-197 Appendix A, so a
# failure here on a key that already passed the key-schedule tests points
# at the cipher rather than at the expansion.
# ---------------------------------------------------------------------------

SP800_38A_PLAINTEXT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)

# (key, expected ciphertext for the four blocks above)
SP800_38A_ECB_VECTORS = (
    (
        bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
        bytes.fromhex(
            "3ad77bb40d7a3660a89ecaf32466ef97"
            "f5d3d58503b9699de785895a96fdbaaf"
            "43b1cd7f598ece23881b00e3ed030688"
            "7b0c785e27e8ad3f8223207104725dd4"
        ),
    ),
    (
        bytes.fromhex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
        bytes.fromhex(
            "bd334f1d6e45f25ff712a214571fa5cc"
            "974104846d0ad3ad7734ecb3ecee4eef"
            "ef7afd2270e2e60adce0ba2face6444e"
            "9a4b41ba738d6c72fb16691603c18e0e"
        ),
    ),
    (
        bytes.fromhex(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
        ),
        bytes.fromhex(
            "f3eed1bdb5d2a03c064b5a7e3db181f8"
            "591ccb10d410ed26dc5ba74a31362870"
            "b6ed21b99ca6f4f9f153e7b1beafed1d"
            "23304b7a39f9f3ff067d8d8f9e24ecc7"
        ),
    ),
)
