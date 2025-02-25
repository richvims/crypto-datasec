# Import the os module to access operating system functions (e.g., generating random bytes)
import os  # Used later for generating the initialization vector (IV)

# Import the random module to generate random numbers
import random  # Used for selecting random primes and for other random selections

# Import isprime and primerange from sympy to work with prime numbers
from sympy import isprime, primerange  # isprime checks if a number is prime; primerange generates primes in a range


# --- Helper functions for padding and unpadding (PKCS#7) ---

def pad(plaintext, block_size=16):
    # Calculate how many padding bytes are needed (block_size - (current length mod block_size))
    padding_len = block_size - (len(plaintext) % block_size)
    # Append padding bytes to plaintext; each padding byte is equal to the number of padding bytes added
    return plaintext + bytes([padding_len] * padding_len)

def unpad(plaintext):
    # Read the value of the last byte to determine how many padding bytes were added
    padding_len = plaintext[-1]
    # Validate that the padding length is within the expected range (1 to 16)
    if padding_len < 1 or padding_len > 16:
        raise ValueError("Invalid padding")
    # Remove the padding bytes and return the original plaintext
    return plaintext[:-padding_len]


# --- Helper functions for converting between bytes and a 4x4 matrix ---
# AES works on a 4x4 byte matrix (state) for each 16-byte block

def bytes2matrix(text):
    # Split the 16-byte array into 4 lists of 4 bytes each (row-major order)
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrix2bytes(matrix):
    # Flatten the 4x4 matrix back into a single bytes object
    # The sum(matrix, []) flattens the list of lists into one list of bytes
    return bytes(sum(matrix, []))

def transpose(matrix):
    # Transpose the matrix (switch rows and columns)
    return [list(x) for x in zip(*matrix)]


# --- AES S-box and Inverse S-box ---
# These tables are used for the byte substitution step in AES

s_box = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

inv_s_box = [
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
]


# --- Galois Field multiplication helper functions ---
# These functions are used to perform multiplication in the finite field GF(2^8)

def xtime(a):
    # Multiply a by 2 in GF(2^8); if the most significant bit is set, XOR with 0x1B (the AES irreducible polynomial)
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1)

def mul(a, b):
    # Multiply two numbers a and b in GF(2^8) using bitwise operations
    p = 0  # Initialize product
    for i in range(8):  # Loop over each bit of b
        if b & 1:  # If the lowest bit of b is 1,
            p ^= a  # add (XOR) a to the product
        hi_bit = a & 0x80  # Check if a's highest bit is set (needed for reduction)
        a = (a << 1) & 0xFF  # Shift a left by one (multiply by 2) and limit to 8 bits
        if hi_bit:  # If the high bit was set,
            a ^= 0x1B  # reduce modulo the irreducible polynomial 0x1B
        b >>= 1  # Shift b right by one to process the next bit
    return p  # Return the product in GF(2^8)


# --- AES core transformations ---

def add_round_key(state, round_key):
    # XOR each byte of the state with the corresponding byte from the round key
    for i in range(4):  # Loop through each row
        for j in range(4):  # Loop through each column
            state[i][j] ^= round_key[i][j]  # XOR the state byte with the round key byte

def sub_bytes(state):
    # Replace each byte in the state with its corresponding byte from the S-box
    for i in range(4):
        for j in range(4):
            state[i][j] = s_box[state[i][j]]

def inv_sub_bytes(state):
    # Replace each byte in the state with its corresponding byte from the inverse S-box
    for i in range(4):
        for j in range(4):
            state[i][j] = inv_s_box[state[i][j]]

def shift_rows(state):
    # Rotate the second row to the left by 1 byte, the third row by 2, and the fourth row by 3
    state[1] = state[1][1:] + state[1][:1]  # Shift row 1 left by 1
    state[2] = state[2][2:] + state[2][:2]  # Shift row 2 left by 2
    state[3] = state[3][3:] + state[3][:3]  # Shift row 3 left by 3

def inv_shift_rows(state):
    # Reverse the row shifts: rotate the second row right by 1 byte, third row by 2, and fourth row by 3
    state[1] = state[1][-1:] + state[1][:-1]  # Shift row 1 right by 1
    state[2] = state[2][-2:] + state[2][:-2]  # Shift row 2 right by 2
    state[3] = state[3][-3:] + state[3][:-3]  # Shift row 3 right by 3

def mix_columns(state):
    # Mix the columns of the state using a fixed polynomial multiplication in GF(2^8)
    for j in range(4):  # Process each column
        col = [state[i][j] for i in range(4)]  # Extract the current column
        t = col[0] ^ col[1] ^ col[2] ^ col[3]  # XOR of all elements in the column
        u = col[0]  # Save the first element for later use
        # Update each byte in the column by mixing with neighbors and using xtime multiplication
        col[0] ^= t ^ xtime(col[0] ^ col[1])
        col[1] ^= t ^ xtime(col[1] ^ col[2])
        col[2] ^= t ^ xtime(col[2] ^ col[3])
        col[3] ^= t ^ xtime(col[3] ^ u)
        # Write the mixed column back into the state
        for i in range(4):
            state[i][j] = col[i]

def inv_mix_columns(state):
    # Reverse the mix columns step using the inverse polynomial multiplication
    for j in range(4):
        col = [state[i][j] for i in range(4)]
        state[0][j] = mul(col[0], 0x0e) ^ mul(col[1], 0x0b) ^ mul(col[2], 0x0d) ^ mul(col[3], 0x09)
        state[1][j] = mul(col[0], 0x09) ^ mul(col[1], 0x0e) ^ mul(col[2], 0x0b) ^ mul(col[3], 0x0d)
        state[2][j] = mul(col[0], 0x0d) ^ mul(col[1], 0x09) ^ mul(col[2], 0x0e) ^ mul(col[3], 0x0b)
        state[3][j] = mul(col[0], 0x0b) ^ mul(col[1], 0x0d) ^ mul(col[2], 0x09) ^ mul(col[3], 0x0e)


# --- Key expansion (for AES-128) ---
# This function expands a 16-byte key into 11 round keys (each a 4x4 matrix)

def key_expansion(key):
    # Convert the 16-byte key into a 4x4 matrix then transpose it so that each column is a word
    key_columns = transpose(bytes2matrix(key))
    # Start with the original key words; AES-128 needs a total of 44 words (4 words per round * 11 rounds)
    round_keys = list(key_columns)
    # rcon holds the round constant for key expansion; it starts with 0x01 followed by three 0x00 bytes
    rcon = [0x01, 0x00, 0x00, 0x00]
    for i in range(4, 44):
        temp = round_keys[i - 1].copy()  # Copy the previous word
        if i % 4 == 0:
            # Every 4th word undergoes a transformation:
            temp = temp[1:] + temp[:1]  # Rotate the word (cyclic left shift)
            temp = [s_box[b] for b in temp]  # Apply the S-box to each byte in the rotated word
            temp[0] ^= rcon[0]  # XOR the first byte with the round constant
            rcon[0] = xtime(rcon[0])  # Update the round constant by multiplying by 2 in GF(2^8)
        # XOR the word 4 positions earlier with temp to generate the new word
        word = [a ^ b for a, b in zip(round_keys[i - 4], temp)]
        round_keys.append(word)  # Append the new word to the list of round keys
    # Group the 44 words into 11 round keys, each represented as a 4x4 matrix
    round_key_matrices = []
    for i in range(0, 44, 4):
        round_key = transpose(round_keys[i:i + 4])
        round_key_matrices.append(round_key)
    return round_key_matrices  # Return the list of round key matrices


# --- AES block encryption and decryption functions ---
# These functions perform AES-128 encryption or decryption on a single 16-byte block

def aes_encrypt_block(block, key):
    state = bytes2matrix(block)  # Convert the 16-byte block into a 4x4 matrix (the AES state)
    round_keys = key_expansion(key)  # Generate all round keys from the key
    add_round_key(state, round_keys[0])  # Initial round: add the first round key
    for i in range(1, 10):
        sub_bytes(state)       # Substitute bytes using the S-box
        shift_rows(state)      # Shift rows (cyclically) in the state
        mix_columns(state)     # Mix the columns of the state
        add_round_key(state, round_keys[i])  # XOR the state with the current round key
    sub_bytes(state)             # Final round: substitute bytes
    shift_rows(state)            # Final round: shift rows
    add_round_key(state, round_keys[10])  # Final round: add the last round key
    return matrix2bytes(state)   # Convert the state back into a 16-byte block and return it

def aes_decrypt_block(block, key):
    state = bytes2matrix(block)  # Convert the ciphertext block into a 4x4 matrix
    round_keys = key_expansion(key)  # Expand the key into round keys
    add_round_key(state, round_keys[10])  # Start decryption by adding the last round key
    inv_shift_rows(state)  # Inverse shift rows to undo the row shifts
    inv_sub_bytes(state)   # Inverse substitute bytes using the inverse S-box
    for i in range(9, 0, -1):
        add_round_key(state, round_keys[i])  # XOR the state with the round key for this round
        inv_mix_columns(state)  # Inverse mix columns to undo the mixing
        inv_shift_rows(state)   # Inverse shift rows to undo the row shifts
        inv_sub_bytes(state)    # Inverse substitute bytes using the inverse S-box
    add_round_key(state, round_keys[0])  # Final step: add the initial round key
    return matrix2bytes(state)   # Convert the decrypted state back to a 16-byte block


# --- Diffie-Hellman Key Exchange functions ---
# These functions generate a shared secret key used as the AES key

def generate_random_primes(count, lower=10, upper=30):
    # Generate a list of all prime numbers between lower and upper limits
    primes = list(primerange(lower, upper))
    # Randomly select "count" primes from the list and return them
    return random.sample(primes, count)

def find_primitive_roots(p):
    roots = []  # Initialize an empty list to store primitive roots
    # For a prime number p, all numbers from 1 to p-1 are candidates for primitive roots
    required_set = {num for num in range(1, p)}
    for g in range(1, p):
        # Compute the set of all values g^powers mod p for powers from 1 to p-1
        actual_set = {pow(g, powers, p) for powers in range(1, p)}
        if required_set == actual_set:  # If g generates all numbers from 1 to p-1, it is a primitive root
            roots.append(g)
    return roots  # Return the list of primitive roots

def power(a, b, p):
    # Print the operation being performed (for demonstration)
    print(f"Computing {a}^{b} mod {p}")
    # Compute a^b mod p and return the result
    return pow(a, b, p)

def diffie_hellman_key_exchange():
    # Display a fancy ASCII art font for visual effect (not essential to the algorithm)
    font = """██████╗ ██╗███████╗███████╗██╗███████╗    ██╗  ██╗███████╗██╗     ██╗     ███╗   ███╗ █████╗ ███╗   ██╗
██╔══██╗██║██╔════╝██╔════╝██║██╔════╝    ██║  ██║██╔════╝██║     ██║     ████╗ ████║██╔══██╗████╗  ██║
██║  ██║██║█████╗  █████╗  ██║█████╗█████╗███████║█████╗  ██║     ██║     ██╔████╔██║███████║██╔██╗ ██║
██║  ██║██║██╔══╝  ██╔══╝  ██║██╔══╝╚════╝██╔══██║██╔══╝  ██║     ██║     ██║╚██╔╝██║██╔══██║██║╚██╗██║
██████╔╝██║██║     ██║     ██║███████╗    ██║  ██║███████╗███████╗███████╗██║ ╚═╝ ██║██║  ██║██║ ╚████║
╚═════╝ ╚═╝╚═╝     ╚═╝     ╚═╝╚══════╝    ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
                                                                                                       """
    print(font)  # Print the ASCII art
    # Generate 5 random prime numbers within the specified range
    prime_array = generate_random_primes(5)
    print("Random Prime Numbers: ", prime_array)  # Display the generated primes
    P = int(input("Choose a prime from the list above: "))  # Ask the user to choose one of these primes
    if P not in prime_array:
        print("Invalid choice.")  # Warn if the choice is not in the list
        exit(1)  # Exit the program if the user input is invalid
    else:
        primitive_roots = find_primitive_roots(P)  # Find primitive roots for the chosen prime
        print(f"Primitive roots of {P} are: {primitive_roots}")  # Display the primitive roots
        G = int(input("Choose a primitive root from the list above: "))  # Let the user choose one primitive root
    print(f"Public parameters: P = {P} (prime), G = {G} (primitive root)")  # Show the public parameters
    # Get Alice's and Bob's private keys from user input
    a = int(input("Please enter Alice's chosen private key (1 < a < P-1) : "))
    b = int(input("Please enter Bob's chosen private key (1 < b < P-1): "))
    print("Private keys chosen:")
    print(f"Alice: a = {a}, Bob: b = {b}\n")
    # Compute Alice's public key (G^a mod P)
    x = power(G, a, P)
    # Compute Bob's public key (G^b mod P)
    y = power(G, b, P)
    print(f"Alice computes public key: G^a mod P = {x}")
    print(f"Bob computes public key: G^b mod P = {y}\n")
    # Compute the shared secret key from Bob's public key raised to Alice's private key (and vice versa)
    ka = power(y, a, P)
    kb = power(x, b, P)
    print(f"Both derive shared key: {ka}\n")
    # Convert the shared secret key into a 16-byte value (AES key) using big-endian byte order
    key = ka.to_bytes(16, 'big')
    return key  # Return the AES key for encryption/decryption


# --- Manual CBC (Cipher Block Chaining) encryption and decryption using our AES functions ---

def manual_cbc_encrypt(plaintext, key, iv):
    # Print an ASCII art header for CBC encryption (for visual effect)
    font = """ █████╗ ███████╗███████╗
██╔══██╗██╔════╝██╔════╝
███████║█████╗  ███████╗
██╔══██║██╔══╝  ╚════██║
██║  ██║███████╗███████║
╚═╝  ╚═╝╚══════╝╚══════╝
                        """
    print(font)
    print("Starting CBC encryption...")  # Inform the user that CBC encryption is starting
    print("Number of blocks = (Size of plaintext / 16) rounded up.\n")
    print(f"Key: {key}\nInitialization vector (IV): {iv}")  # Display the key and IV used

    plaintext = pad(plaintext, 16)  # Pad the plaintext so its length is a multiple of 16 bytes
    # Divide the padded plaintext into 16-byte blocks
    blocks = [plaintext[i:i + 16] for i in range(0, len(plaintext), 16)]
    ciphertext, previous = b'', iv  # Initialize ciphertext and set the first "previous" block as the IV
    for i, block in enumerate(blocks):
        print(f"\nEncrypting block {i + 1}: {block}")  # Display the current plaintext block being processed
        # XOR the current block with the previous ciphertext block (or IV for the first block)
        xor_block = bytes([a ^ b for a, b in zip(block, previous)])
        print(f"XOR block with previous block: {xor_block}")
        # Encrypt the XOR result using our AES block encryption function
        encrypted = aes_encrypt_block(xor_block, key)
        ciphertext += encrypted  # Append the encrypted block to the overall ciphertext
        print(f"Encrypted block {i + 1}: {encrypted}")
        previous = encrypted  # Update previous to the current ciphertext block for chaining
    return ciphertext  # Return the complete ciphertext

def manual_cbc_decrypt(ciphertext, key, iv):
    print("\nStarting CBC decryption...")  # Inform the user that CBC decryption is starting
    # Split the ciphertext into 16-byte blocks
    blocks = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]
    plaintext, previous = b'', iv  # Initialize the plaintext and set previous to the IV
    for i, block in enumerate(blocks):
        # Decrypt the current ciphertext block using our AES block decryption function
        decrypted = aes_decrypt_block(block, key)
        # XOR the decrypted block with the previous ciphertext block (or IV for the first block)
        xor_block = bytes([a ^ b for a, b in zip(decrypted, previous)])
        print(f"Decrypted block {i + 1}: {decrypted}")
        print(f"XOR decrypted block with previous block to get plaintext block {i + 1}: {xor_block}")
        plaintext += xor_block  # Append the result to the overall plaintext
        previous = block  # Update previous with the current ciphertext block for the next round
    return unpad(plaintext)  # Remove padding from the final plaintext and return it

def introduce_bit_error(data):
    # Convert the byte data into a list of integers for mutability
    data_list = list(data)
    index = 11  # Choose a fixed index (or random index) where a bit error will be introduced
    #index = random.randint(0, len(data_list) - 1)
    data_list[index] ^= 0x01  # Flip the least significant bit at the chosen index
    return bytes(data_list)  # Convert the list back to bytes and return the corrupted data


# --- Main demonstration function ---
# This function ties everything together: key exchange, encryption, decryption, and error simulation

def aes_demo():
    # Run Diffie-Hellman key exchange to get a shared AES key
    key = diffie_hellman_key_exchange()
    # Generate a random 16-byte Initialization Vector (IV) using os.urandom for cryptographic randomness
    iv = os.urandom(16)
    # Prompt the user to input a plaintext string and convert it to bytes (UTF-8 encoding)
    plaintext = input("Please enter the string to be encrypted: ").encode('utf-8')
    print("\nPlaintext:", plaintext, "\n")
    # Encrypt the plaintext using our manual CBC encryption function
    ciphertext = manual_cbc_encrypt(plaintext, key, iv)
    print("\nFinal Ciphertext:", ciphertext)
    # Decrypt the ciphertext back to plaintext using our manual CBC decryption function
    decrypted = manual_cbc_decrypt(ciphertext, key, iv)
    print("\nDecrypted Text:", decrypted, "\n\n")
    # Print an ASCII art header for completion (visual effect)
    font = """██████╗ ██╗████████╗    ███████╗██████╗ ██████╗  ██████╗ ██████╗ 
██╔══██╗██║╚══██╔══╝    ██╔════╝██╔══██╗██╔══██╗██╔═══██╗██╔══██╗
██████╔╝██║   ██║       █████╗  ██████╔╝██████╔╝██║   ██║██████╔╝
██╔══██╗██║   ██║       ██╔══╝  ██╔══██╗██╔══██╗██║   ██║██╔══██╗
██████╔╝██║   ██║       ███████╗██║  ██║██║  ██║╚██████╔╝██║  ██║
╚═════╝ ╚═╝   ╚═╝       ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
                                                                 """
    print(font)
    # Introduce a bit error in the ciphertext to simulate data corruption
    corrupted_ciphertext = introduce_bit_error(ciphertext)
    print("\nCorrupted Ciphertext:", corrupted_ciphertext)
    try:
        # Attempt to decrypt the corrupted ciphertext
        decrypted = manual_cbc_decrypt(corrupted_ciphertext, key, iv)
        print("\nDecrypted text after bit error:", decrypted)
    except Exception as e:
        # If decryption fails (e.g., due to padding error), catch the exception and print the error message
        print("Decryption failed due to bit error:", e)

# Ensure that the demo runs only when this script is executed directly (not when imported as a module)
if __name__ == "__main__":
    aes_demo()  # Run the demonstration function
