import time  # Import time module for timing operations
import math  # Import math module for mathematical functions (e.g., ceil)

# Affine Cipher Functions

def gcd(a, b):  # Define function to compute greatest common divisor of a and b
    while b != 0:  # Loop until b becomes 0
        a, b = b, a % b  # Update a and b using the Euclidean algorithm
    return a  # Return the computed greatest common divisor

def mod_inverse(a, m):  # Define function to compute the modular inverse of a under modulo m
    for i in range(1, m):  # Iterate through all numbers from 1 to m-1
        if (a * i) % m == 1:  # Check if i is the modular inverse (i.e., (a*i) mod m equals 1)
            return i  # Return the modular inverse if found
    return None  # Return None if no modular inverse exists

def affine_encrypt(text, a, b):  # Define function to encrypt text using the Affine cipher with keys a and b
    encrypted_text = ""  # Initialize an empty string to hold the encrypted text
    for char in text:  # Loop through each character in the input text
        if char.isalpha():  # Check if the character is an alphabet letter
            x = ord(char.lower()) - ord('a')  # Convert letter to its index (0-25)
            encrypted_text += chr(((a * x + b) % 26) + ord('a'))  # Encrypt character and append the result
        else:  # For non-alphabet characters
            encrypted_text += char  # Append the character unchanged
    return encrypted_text  # Return the complete encrypted text

def affine_decrypt(ciphertext, a, b):  # Define function to decrypt ciphertext using the Affine cipher with keys a and b
    decrypted_text = ""  # Initialize an empty string to hold the decrypted text
    a_inv = mod_inverse(a, 26)  # Compute the modular inverse of a modulo 26
    if a_inv is None:  # Check if the modular inverse does not exist
        return "Invalid Key"  # Return error message if key is invalid
    for char in ciphertext:  # Loop through each character in the ciphertext
        if char.isalpha():  # Check if the character is an alphabet letter
            y = ord(char.lower()) - ord('a')  # Convert letter to its index (0-25)
            decrypted_text += chr(((a_inv * (y - b)) % 26) + ord('a'))  # Decrypt character and append the result
        else:  # For non-alphabet characters
            decrypted_text += char  # Append the character unchanged
    return decrypted_text  # Return the complete decrypted text

# Columnar Transposition Cipher Functions

def get_key_order(key):  # Define function to determine the order of columns based on the keyword
    return sorted(range(len(key)), key=lambda k: key[k])  # Return indices of key characters sorted by the character value

def columnar_encrypt(text, key):  # Define function to encrypt text using the Columnar Transposition cipher with a given key
    key_order = get_key_order(key)  # Get the order of columns based on the key
    num_cols = len(key)  # Determine the number of columns from the length of the key
    num_rows = math.ceil(len(text) / num_cols)  # Calculate the number of rows needed in the grid

    grid = [['' for _ in range(num_cols)] for _ in range(num_rows)]  # Create a grid (list of lists) with empty strings
    index = 0  # Initialize index to track position in the text
    for i in range(num_rows):  # Loop over each row in the grid
        for j in range(num_cols):  # Loop over each column in the grid
            if index < len(text):  # If there are characters left in the text
                grid[i][j] = text[index]  # Place the current character into the grid cell
                index += 1  # Increment the index
            else:  # If text has been exhausted
                grid[i][j] = 'X'  # Pad the grid with 'X'
    
    encrypted_text = "".join(grid[row][col] for col in key_order for row in range(num_rows))  # Read columns in key order to form the encrypted text
    return encrypted_text  # Return the encrypted text

def columnar_decrypt(ciphertext, key):  # Define function to decrypt ciphertext using the Columnar Transposition cipher with a given key
    key_order = get_key_order(key)  # Get the order of columns based on the key
    num_cols = len(key)  # Determine the number of columns from the key length
    num_rows = math.ceil(len(ciphertext) / num_cols)  # Calculate the number of rows required for the grid

    grid = [['' for _ in range(num_cols)] for _ in range(num_rows)]  # Create a grid with empty strings
    index = 0  # Initialize index to track position in the ciphertext
    for col in key_order:  # Loop over each column in the order defined by key_order
        for row in range(num_rows):  # Loop over each row in the grid
            if index < len(ciphertext):  # If there are characters left in the ciphertext
                grid[row][col] = ciphertext[index]  # Fill the grid cell with the current ciphertext character
                index += 1  # Increment the index

    decrypted_text = "".join("".join(row) for row in grid).rstrip('X')  # Read the grid row-wise and remove any padding 'X'
    return decrypted_text  # Return the decrypted text

# Product Cipher (Combination of Affine + Double Columnar Transposition)

def product_cipher_encrypt(text, affine_a, affine_b, key1, key2):  # Define function to encrypt text using a combination of Affine and Double Columnar Transposition ciphers
    # Affine Encryption
    start_time = time.time()  # Record the start time for affine encryption
    affine_encrypted = affine_encrypt(text, affine_a, affine_b)  # Encrypt the text using the Affine cipher
    affine_time = time.time() - start_time  # Calculate the time taken for affine encryption

    # Double Columnar Transposition
    start_time = time.time()  # Record the start time for columnar transposition
    first_enc = columnar_encrypt(affine_encrypted, key1)  # Perform the first columnar encryption using key1
    final_enc = columnar_encrypt(first_enc, key2)  # Perform the second columnar encryption using key2
    columnar_time = time.time() - start_time  # Calculate the time taken for columnar transposition

    total_time = affine_time + columnar_time  # Sum the total encryption time
    return final_enc, total_time  # Return the final encrypted text and the total encryption time

def product_cipher_decrypt(ciphertext, affine_a, affine_b, key1, key2):  # Define function to decrypt ciphertext using the product cipher
    # Double Columnar Transposition Decryption
    start_time = time.time()  # Record the start time for columnar decryption
    first_dec = columnar_decrypt(ciphertext, key2)  # Perform the first columnar decryption using key2
    columnar_dec = columnar_decrypt(first_dec, key1)  # Perform the second columnar decryption using key1
    columnar_time = time.time() - start_time  # Calculate the time taken for columnar decryption

    # Affine Decryption
    start_time = time.time()  # Record the start time for affine decryption
    final_dec = affine_decrypt(columnar_dec, affine_a, affine_b)  # Decrypt the text using the Affine cipher
    affine_time = time.time() - start_time  # Calculate the time taken for affine decryption

    total_time = columnar_time + affine_time  # Sum the total decryption time
    return final_dec, total_time  # Return the final decrypted text and the total decryption time

# User Input & Execution

if __name__ == "__main__":  # Check if the script is run as the main program
    text = input("Enter plaintext: ")  # Prompt the user to enter the plaintext
    
    affine_a, affine_b = 5, 8  # Set Affine cipher keys (a must be coprime with 26)
    key1 = "cipher"  # Define the first key for columnar transposition
    key2 = "secure"  # Define the second key for columnar transposition

    # Encryption
    encrypted_text, encryption_time = product_cipher_encrypt(text, affine_a, affine_b, key1, key2)  # Encrypt the text using the product cipher and record the encryption time
    print("\nEncrypted Text:", encrypted_text)  # Print the encrypted text
    print("Encryption Time:", f"{encryption_time:.6f} seconds")  # Print the encryption time formatted to six decimal places

    # Decryption
    decrypt_input = input("\nEnter ciphertext to decrypt: ")  # Prompt the user to enter the ciphertext for decryption
    decrypted_text, decryption_time = product_cipher_decrypt(decrypt_input, affine_a, affine_b, key1, key2)  # Decrypt the ciphertext and record the decryption time
    print("Decrypted Text:", decrypted_text)  # Print the decrypted text
    print("Decryption Time:", f"{decryption_time:.6f} seconds")  # Print the decryption time formatted to six decimal places
