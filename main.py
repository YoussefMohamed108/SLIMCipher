
SBOX = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]
INV_SBOX = [0] * 16
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i  # reverse lookup for decryption

PBOX = [7, 13, 1, 8, 11, 14, 2, 5, 4, 10, 15, 0, 3, 6, 9, 12]
INV_PBOX = [0] * 16
for i, v in enumerate(PBOX):
    INV_PBOX[v] = i  # reverse lookup for decryption



def substitute(word, box=SBOX):
    return (box[(word >> 12) & 0xF] << 12 |
            box[(word >> 8)  & 0xF] << 8  |
            box[(word >> 4)  & 0xF] << 4  |
            box[ word        & 0xF])


def permute(word, box=PBOX):
    result = 0
    for i in range(16):
        bit = (word >> i) & 1          # extract bit i of the input
        result |= bit << box[i]        # place it at bit box[i] of the output
    return result

def generate_round_keys(master_key):
    round_keys = []

    # Ensure the value fits within 80 bits
    key = master_key & 0xFFFFFFFFFFFFFFFFFFFF

    # Extract the first 5 sub-keys directly from the 80-bit key (LSB first)
    for i in range(5):
        round_keys.append((key >> (i * 16)) & 0xFFFF)

    # Generate the remaining 27 sub-keys
    for _ in range(27):
        key_lsb = key & 0xFFFFFFFFFF          # lower 40 bits
        key_msb = (key >> 40) & 0xFFFFFFFFFF  # upper 40 bits

        # Rotate KeyLSB left by 2 (40-bit circular)
        lsb_rot = ((key_lsb << 2) | (key_lsb >> 38)) & 0xFFFFFFFFFF

        # XOR rotated KeyLSB with KeyMSB
        xored = lsb_rot ^ key_msb

        # Apply S-Box to the upper 16 bits of the XOR result (bits 24-39)
        sboxed = substitute((xored >> 24) & 0xFFFF)

        # Rotate KeyMSB left by 3 (40-bit circular)
        msb_rot = ((key_msb << 3) | (key_msb >> 37)) & 0xFFFFFFFFFF

        # Round sub-key = sboxed XOR upper 16 bits of rotated KeyMSB
        round_keys.append(sboxed ^ ((msb_rot >> 24) & 0xFFFF))

        # Update key state for next iteration
        key = (msb_rot << 40) | lsb_rot

    return round_keys  # list of 32 integers, each 16 bits


def encrypt(plaintext, round_keys):
    U = (plaintext >> 16) & 0xFFFF
    D =  plaintext        & 0xFFFF

    for rk in round_keys:
        f = permute(substitute(rk ^ D))  # round function
        U, D = D, U ^ f                  # Feistel swap

    return (U << 16) | D


def decrypt(ciphertext, round_keys):
    U = (ciphertext >> 16) & 0xFFFF
    D =  ciphertext        & 0xFFFF

    for rk in reversed(round_keys):
        f = permute(substitute(rk ^ U))  # round function (applied to U)
        U, D = D ^ f, U                  # undo Feistel swap

    return (U << 16) | D

def validate_hex_input(prompt, bits):
    """Read and validate a hex string, ensuring it fits within the given bit width."""
    max_digits = bits // 4
    while True:
        try:
            user_input = input(prompt).strip()
            value = int(user_input, 16)
            if value >> bits == 0:
                return value
            else:
                print(f"  Error: Value exceeds {bits}-bit limit "
                      f"(max {max_digits} hex digits, you entered {len(user_input)})")
        except ValueError:
            print(f"  Error: '{user_input}' is not a valid hexadecimal number.")


def run_tests():
    print("\n--- Test Cases ---")
    tests = [
        (0x00000000, 0x00000000000000000000),
        (0xFFFFFFFF, 0xFFFFFFFFFFFFFFFFFFFF),
        (0xABCD1234, 0x0123456789ABCDEF0123),
        (0x12345678, 0xDEADBEEFCAFEBABE1234),
        (0x48273619, 0x9A8B7C6D5E4F3A2B1C0D),
        (0xF0E1D2C3, 0xB4A59687786954B3C2D1),
    ]
    all_pass = True
    for pt, key in tests:
        rks = generate_round_keys(key)
        ct  = encrypt(pt, rks)
        dec = decrypt(ct, rks)
        status = "PASS" if dec == pt else "FAIL"
        if status == "FAIL":
            all_pass = False
        print(f"  PT={pt:08X}  Key={key:020X}  CT={ct:08X}  Dec={dec:08X}  {status}")
    print(f"\n  Overall: {'All tests PASSED' if all_pass else 'Some tests FAILED'}")


def run_interactive():
    print("\n--- Interactive Mode ---")
    print("Enter values as hexadecimal (e.g. ABCD1234)\n")

    pt  = validate_hex_input("  Plaintext  (32-bit  / 8 hex digits) : ", 32)
    key = validate_hex_input("  Secret Key (80-bit / 20 hex digits) : ", 80)

    rks = generate_round_keys(key)
    ct  = encrypt(pt, rks)
    dec = decrypt(ct, rks)

    print(f"\n  Plaintext  : {pt:08X}")
    print(f"  Key        : {key:020X}")
    print(f"  Ciphertext : {ct:08X}")
    print(f"  Decrypted  : {dec:08X}")
    print(f"  Match      : {'Yes - Decryption successful' if dec == pt else 'No - ERROR'}")


if __name__ == "__main__":
    while True:
        print("\nSLIM Block Cipher | 32-bit block | 80-bit key | 32 rounds")
        print("  1 - Run test cases")
        print("  2 - Interactive")
        print("  3 - Both")
        print("  4 - Exit")
        choice = input("Choice: ").strip()

        if choice == "1":
            run_tests()
        elif choice == "2":
            run_interactive()
        elif choice == "3":
            run_tests()
            run_interactive()
        elif choice == "4":
            break
        else:
            print("  Error: Please enter 1, 2, 3, or 4.")