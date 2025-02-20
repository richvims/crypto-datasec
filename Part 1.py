import time  # Import the time module to measure execution time.
import math  # Import the math module for mathematical functions like ceil.

# Affine Cipher Functions

def gcd(a, b):  # Define a function to compute the Greatest Common Divisor (GCD) of a and b.
    while b != 0:  # Loop until b becomes 0.
        a, b = b, a % b  # Update a to b and b to the remainder of a divided by b.
    return a  # Return a, which is the GCD of the original a and b.

def mod_inverse(a, m):  # Define a function to find the modular multiplicative inverse of a modulo m.
    for i in range(1, m):  # Loop through potential inverse values from 1 to m-1.
        if (a * i) % m == 1:  # Check if multiplying a by i modulo m gives 1.
            return i  # Return i if it is the modular inverse.
    return None  # Return None if no modular inverse exists (i.e., a and m are not coprime).

def affine_encrypt(text, a, b):  # Define a function to encrypt text using the Affine Cipher with keys a and b.
    encrypted_text = ""  # Initialize an empty string to store the encrypted text.
    for char in text:  # Iterate over each character in the input text.
        if char.isalpha():  # Check if the character is an alphabetic letter.
            x = ord(char.lower()) - ord('a')  # Convert the character to a numerical index (0 for 'a', 1 for 'b', etc.).
            encrypted_text += chr(((a * x + b) % 26) + ord('a'))  # Apply the Affine Cipher formula and convert back to a character.
        else:  # If the character is not alphabetic,
            encrypted_text += char  # Append it unchanged to the encrypted text.
    return encrypted_text  # Return the complete encrypted text.

def affine_decrypt(ciphertext, a, b):  # Define a function to decrypt ciphertext using the Affine Cipher with keys a and b.
    decrypted_text = ""  # Initialize an empty string to store the decrypted text.
    a_inv = mod_inverse(a, 26)  # Calculate the modular inverse of a modulo 26.
    if a_inv is None:  # If no modular inverse exists,
        return "Invalid Key"  # Return an error message indicating an invalid key.

    for char in ciphertext:  # Iterate over each character in the ciphertext.
        if char.isalpha():  # Check if the character is an alphabetic letter.
            y = ord(char.lower()) - ord('a')  # Convert the character to its numerical index.
            decrypted_text += chr(((a_inv * (y - b)) % 26) + ord('a'))  # Apply the decryption formula and convert back to a character.
        else:  # If the character is not alphabetic,
            decrypted_text += char  # Append it unchanged to the decrypted text.
    return decrypted_text  # Return the complete decrypted text.

# Columnar Transposition Cipher Functions

def get_key_order(key):  # Define a function to determine the order of columns based on the provided key.
    return sorted(range(len(key)), key=lambda k: key[k])  # Return a list of indices sorted by the corresponding character in the key.

def columnar_encrypt(text, key):  # Define a function to encrypt text using the Columnar Transposition Cipher with a given key.
    key_order = get_key_order(key)  # Determine the column order based on the key.
    num_cols = len(key)  # The number of columns is equal to the length of the key.
    num_rows = math.ceil(len(text) / num_cols)  # Calculate the number of rows required to fit the text.

    grid = [['' for _ in range(num_cols)] for _ in range(num_rows)]  # Create a grid (2D list) initialized with empty strings.
    index = 0  # Initialize an index to traverse the text.
    for i in range(num_rows):  # Loop over each row.
        for j in range(num_cols):  # Loop over each column in the row.
            if index < len(text):  # If there are still characters left in the text,
                grid[i][j] = text[index]  # Place the character into the grid cell.
                index += 1  # Increment the index to move to the next character.
            else:  # If the text is exhausted,
                grid[i][j] = 'X'  # Fill the remaining cells with the padding character 'X'.

    encrypted_text = "".join(grid[row][col] for col in key_order for row in range(num_rows))  # Read the grid column-wise in the order specified by key_order and concatenate to form the encrypted text.
    return encrypted_text  # Return the encrypted text.

def columnar_decrypt(ciphertext, key):  # Define a function to decrypt ciphertext using the Columnar Transposition Cipher with a given key.
    key_order = get_key_order(key)  # Determine the column order based on the key.
    num_cols = len(key)  # The number of columns is equal to the length of the key.
    num_rows = math.ceil(len(ciphertext) / num_cols)  # Calculate the number of rows based on the ciphertext length and number of columns.

    grid = [['' for _ in range(num_cols)] for _ in range(num_rows)]  # Create an empty grid (2D list) with the calculated dimensions.
    index = 0  # Initialize an index to traverse the ciphertext.
    for col in key_order:  # Iterate over each column index in the order defined by the key.
        for row in range(num_rows):  # Iterate over each row for the current column.
            if index < len(ciphertext):  # If there are still characters left in the ciphertext,
                grid[row][col] = ciphertext[index]  # Place the character into the corresponding grid cell.
                index += 1  # Increment the index to move to the next character.

    decrypted_text = "".join("".join(row) for row in grid).rstrip('X')  # Concatenate all rows to form the decrypted text and remove any trailing padding 'X'.
    return decrypted_text  # Return the decrypted text.

# Product Cipher (Combination of Affine + Double Columnar Transposition)

def product_cipher_encrypt(text, affine_a, affine_b, key1, key2):  # Define a function to encrypt text using a combination of Affine and Double Columnar Transposition ciphers.
    # Affine Encryption
    start_time = time.time()  # Record the current time to measure the duration of the affine encryption.
    affine_encrypted = affine_encrypt(text, affine_a, affine_b)  # Encrypt the text using the Affine Cipher.
    affine_time = time.time() - start_time  # Calculate the time taken for the affine encryption process.

    # Double Columnar Transposition
    start_time = time.time()  # Record the current time to measure the duration of the columnar transpositions.
    first_enc = columnar_encrypt(affine_encrypted, key1)  # Apply the first columnar transposition using key1.
    final_enc = columnar_encrypt(first_enc, key2)  # Apply the second columnar transposition using key2.
    columnar_time = time.time() - start_time  # Calculate the time taken for both columnar transpositions.

    total_time = affine_time + columnar_time  # Sum the times to get the total encryption time.
    return final_enc, total_time  # Return the final encrypted text along with the total encryption time.

def product_cipher_decrypt(ciphertext, affine_a, affine_b, key1, key2):  # Define a function to decrypt ciphertext encrypted with the product cipher.
    # Double Columnar Transposition Decryption
    start_time = time.time()  # Record the current time to measure the duration of the columnar decryption.
    first_dec = columnar_decrypt(ciphertext, key2)  # Reverse the second columnar transposition using key2.
    columnar_dec = columnar_decrypt(first_dec, key1)  # Reverse the first columnar transposition using key1.
    columnar_time = time.time() - start_time  # Calculate the time taken for both columnar decryption steps.

    # Affine Decryption
    start_time = time.time()  # Record the current time to measure the duration of the affine decryption.
    final_dec = affine_decrypt(columnar_dec, affine_a, affine_b)  # Decrypt the intermediate text using the Affine Cipher decryption.
    affine_time = time.time() - start_time  # Calculate the time taken for the affine decryption process.

    total_time = columnar_time + affine_time  # Sum the times to get the total decryption time.
    return final_dec, total_time  # Return the final decrypted text along with the total decryption time.

# User Input & Execution

if __name__ == "__main__":  # Check if this script is executed as the main program.
    text = input("Enter plaintext: ")  # Prompt the user to input the plaintext message for encryption.
    
    affine_a, affine_b = 5, 8  # Define the Affine Cipher keys (note: affine_a must be coprime with 26 for decryption to work).
    key1 = "cipher"  # Set the first key for the columnar transposition.
    key2 = "secure"  # Set the second key for the columnar transposition.

    # Encryption
    encrypted_text, encryption_time = product_cipher_encrypt(text, affine_a, affine_b, key1, key2)  # Encrypt the plaintext using the product cipher and capture the encryption time.
    print("\nEncrypted Text:", encrypted_text)  # Print the resulting encrypted text.
    print("Encryption Time:", f"{encryption_time:.6f} seconds")  # Print the encryption time formatted to six decimal places.

    # Decryption
    decrypt_input = input("\nEnter ciphertext to decrypt: ")  # Prompt the user to input the ciphertext message for decryption.
    decrypted_text, decryption_time = product_cipher_decrypt(decrypt_input, affine_a, affine_b, key1, key2)  # Decrypt the ciphertext using the product cipher and capture the decryption time.
    print("Decrypted Text:", decrypted_text)  # Print the resulting decrypted text.
    print("Decryption Time:", f"{decryption_time:.6f} seconds")  # Print the decryption time formatted to six decimal places.
