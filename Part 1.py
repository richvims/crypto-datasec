import time
import math

# Affine Cipher Functions
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None

def affine_encrypt(text, a, b):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            x = ord(char.lower()) - ord('a')
            encrypted_text += chr(((a * x + b) % 26) + ord('a'))
        else:
            encrypted_text += char
    return encrypted_text

def affine_decrypt(ciphertext, a, b):
    decrypted_text = ""
    a_inv = mod_inverse(a, 26)
    if a_inv is None:
        return "Invalid Key"

    for char in ciphertext:
        if char.isalpha():
            y = ord(char.lower()) - ord('a')
            decrypted_text += chr(((a_inv * (y - b)) % 26) + ord('a'))
        else:
            decrypted_text += char
    return decrypted_text

# Columnar Transposition Cipher Functions
def get_key_order(key):
    return sorted(range(len(key)), key=lambda k: key[k])

def columnar_encrypt(text, key):
    key_order = get_key_order(key)
    num_cols = len(key)
    num_rows = math.ceil(len(text) / num_cols)

    grid = [['' for _ in range(num_cols)] for _ in range(num_rows)]
    index = 0
    for i in range(num_rows):
        for j in range(num_cols):
            if index < len(text):
                grid[i][j] = text[index]
                index += 1
            else:
                grid[i][j] = 'X'

    encrypted_text = "".join(grid[row][col] for col in key_order for row in range(num_rows))
    return encrypted_text

def columnar_decrypt(ciphertext, key):
    key_order = get_key_order(key)
    num_cols = len(key)
    num_rows = math.ceil(len(ciphertext) / num_cols)

    grid = [['' for _ in range(num_cols)] for _ in range(num_rows)]
    index = 0
    for col in key_order:
        for row in range(num_rows):
            if index < len(ciphertext):
                grid[row][col] = ciphertext[index]
                index += 1

    decrypted_text = "".join("".join(row) for row in grid).rstrip('X')
    return decrypted_text

# Product Cipher (Combination of Affine + Double Columnar Transposition)
def product_cipher_encrypt(text, affine_a, affine_b, key1, key2):
    # Affine Encryption
    start_time = time.time()
    affine_encrypted = affine_encrypt(text, affine_a, affine_b)
    affine_time = time.time() - start_time

    # Double Columnar Transposition
    start_time = time.time()
    first_enc = columnar_encrypt(affine_encrypted, key1)
    final_enc = columnar_encrypt(first_enc, key2)
    columnar_time = time.time() - start_time

    total_time = affine_time + columnar_time
    return final_enc, total_time

def product_cipher_decrypt(ciphertext, affine_a, affine_b, key1, key2):
    # Double Columnar Transposition Decryption
    start_time = time.time()
    first_dec = columnar_decrypt(ciphertext, key2)
    columnar_dec = columnar_decrypt(first_dec, key1)
    columnar_time = time.time() - start_time

    # Affine Decryption
    start_time = time.time()
    final_dec = affine_decrypt(columnar_dec, affine_a, affine_b)
    affine_time = time.time() - start_time

    total_time = columnar_time + affine_time
    return final_dec, total_time

# User Input & Execution
if __name__ == "__main__":
    text = input("Enter plaintext: ")
    
    affine_a, affine_b = 5, 8  # Affine Cipher keys (a must be coprime with 26)
    key1 = "cipher"
    key2 = "secure"

    # Encryption
    encrypted_text, encryption_time = product_cipher_encrypt(text, affine_a, affine_b, key1, key2)
    print("\nEncrypted Text:", encrypted_text)
    print("Encryption Time:", f"{encryption_time:.6f} seconds")

    # Decryption
    decrypt_input = input("\nEnter ciphertext to decrypt: ")
    decrypted_text, decryption_time = product_cipher_decrypt(decrypt_input, affine_a, affine_b, key1, key2)
    print("Decrypted Text:", decrypted_text)
    print("Decryption Time:", f"{decryption_time:.6f} seconds")
