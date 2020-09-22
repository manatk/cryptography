# Caesar Cipher
# Arguments: string, integer
# Returns: string
def encrypt_caesar(plaintext, offset):
    encrypted_text = ""
    updated_characters = offset_characters(offset)
    print (updated_characters)
    for i in plaintext:
        if ord(i) >= ord('A') and ord(i) <= ord('Z'):
            print (i)
            encrypted_text = encrypted_text + updated_characters[i]
        else:
            encrypted_text = encrypted_text + i

    print ("Encrypted is", encrypted_text)

def offset_characters(offset):
    updated_characters = {}
    for i in range (ord('A'),ord('Z')+1):
        if (i + offset > ord('Z')):
            #print (((i+offset) - ord('A')) % 26)
            new_ASCII = ord('A') + (((i+offset) - ord('A')) % 26)
        else:
            new_ASCII = i + offset

        updated_characters[chr(i)] = chr(new_ASCII)
    return updated_characters

def decrypt_characters (offset):
    updated_characters = {}

    for i in range (ord('A'),ord('Z')+1):
        if (i - offset < ord('A')):
            new_ASCII = ord('Z') - (((i+offset) - ord('A')) % 26)
        else:
            new_ASCII = i - offset

        updated_characters[chr(i)] = chr(new_ASCII)
    return updated_characters

# Arguments: string, integer
# Returns: string
def decrypt_caesar(ciphertext, offset):
    decrypted_text = ""
    decrypted_characters = decrypt_characters(offset)
    print (decrypted_characters)
    for i in ciphertext:
        if ord(i) >= ord('A') and ord(i) <= ord('Z'):
            #print (i)
            decrypted_text = decrypted_text + decrypted_characters[i]
        else:
            decrypted_text = decrypted_text + i

    print ("Decrypted is", decrypted_text)

    #print (((i+offset) - ord('A')) % 25)
    #pass

# Vigenere Cipher
# Arguments: string, string
# Returns: string
def encrypt_vigenere(plaintext, keyword):
    pass

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
    encrypt_caesar("BUZZ", 2)
    decrypt_caesar("DWBB", 2)
    # Testing code here
    pass

if __name__ == "__main__":
    main()
