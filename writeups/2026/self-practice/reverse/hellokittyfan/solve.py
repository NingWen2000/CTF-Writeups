"""Solve the supplied decompiled key check using 32-bit machine arithmetic.

Assumes a 32-bit multiply and arithmetic right shift (SAR).
Does not execute or modify the crackme.
"""


def signed32(value):
    value &= 0xFFFFFFFF
    return value if value < 0x80000000 else value - 0x100000000


def accepts(value):
    if not -(1 << 31) <= value < (1 << 31):
        return False  # Windows stoi accepts signed 32-bit integers.
    doubled = signed32(value * 2)
    return value != 0 and ((doubled >> 20) & 0xFFFFFF80) == 0xFFFFFC00


def solve_ranges():
    # Before masking, the shifted result can be -1024 through -897.
    shifted_min = signed32(0xFFFFFC00)
    shifted_max = shifted_min + 0x7F
    doubled_min = shifted_min << 20
    doubled_max = ((shifted_max + 1) << 20) - 1
    # Undo multiplication, including its positive-input wraparound branch.
    return [
        ((doubled_min + wrap + 1) // 2, (doubled_max + wrap) // 2)
        for wrap in (0, 1 << 32)
    ]


def main():
    ranges = solve_ranges()
    for lower, upper in ranges:
        assert accepts(lower) and accepts(upper)
        assert accepts((lower + upper) // 2)
        assert not accepts(lower - 1) and not accepts(upper + 1)
    assert not accepts(0)
    assert not accepts(-(1 << 31) - 1)
    assert not accepts(1 << 31)

    key = ranges[1][0]
    print(f"Key: {key}")
    print("Accepted integer ranges (inclusive):")
    for lower, upper in ranges:
        print(f"  {lower} .. {upper}")
    print(f"32-bit doubled: 0x{(key * 2) & 0xFFFFFFFF:08X}")
    print(f"After SAR 20:   0x{(signed32(key * 2) >> 20) & 0xFFFFFFFF:08X}")
    print("Model boundary checks passed; this script does not run the executable.")


if __name__ == "__main__":
    main()
