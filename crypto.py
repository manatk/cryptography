import string
# Caesar Cipher
# Arguments: string, integer
# Returns: string

def encrypt_caesar(plaintext, offset):
    encrypted_text = ""
    for character in plaintext:
        encrypted_character = offset_character(character, offset)
        encrypted_text = encrypted_text + encrypted_character
    #print("Encrypted is", encrypted_text)
    return encrypted_text

def offset_character(character, offset):
    #print (character)
    if character not in string.ascii_uppercase:
        return character
    else:
        char_index = ord(character) - ord('A')
        final_index = (char_index + offset) % 26

        return chr(final_index + ord('A'))

# Arguments: string, integer
# Returns: string
def decrypt_caesar(ciphertext, offset):

    decrypt_offset = offset * -1
    decrypted_text = ""
    for character in ciphertext:
        decrypted_character = offset_character(character, decrypt_offset)
        decrypted_text = decrypted_text + decrypted_character
    #print("Encrypted is", encrypted_text)
    return decrypted_text

# Vigenere Cipher
# Arguments: string, string
# Returns: string
def encrypt_vigenere(plaintext, keyword):
    #pass

# Arguments: string, string
# Returns: string
def decrypt_vigenere(ciphertext, keyword):
    pass

# Merkle-Hellman Knapsack Cryptosystem
# Arguments: integer
# Returns: tuple (W, Q, R) - W a length-n tuple of integers, Q and R both integers
def generate_private_key(n=8):
    pass

# Arguments: tuple (W, Q, R) - W a length-n tuple of integers, Q and R both integers
# Returns: tuple B - a length-n tuple of integers
def create_public_key(private_key):
    pass

# Arguments: string, tuple (W, Q, R)
# Returns: list of integers
def encrypt_mhkc(plaintext, public_key):
    pass

# Arguments: list of integers, tuple B - a length-n tuple of integers
# Returns: bytearray or str of plaintext
def decrypt_mhkc(ciphertext, private_key):
    pass

def main():
    print(encrypt_caesar("BUZZ", 2))
    print (decrypt_caesar("DWBB", 2))
    # Testing code here
    pass

if __name__ == "__main__":
    main()
