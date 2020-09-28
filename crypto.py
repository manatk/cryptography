import string
import random
import math
# Caesar Cipher
# Arguments: string, integer
# Returns: string

def encrypt_caesar(plaintext, offset):
    encrypted_text = ""
    #loop through each character in the text and shift it
    for character in plaintext:
        #calling helper function which offsets the character
        encrypted_character = offset_character(character, offset)
        encrypted_text = encrypted_text + encrypted_character
    return encrypted_text

#Helper function which offsets characters by a given value. I chose to make a helper function since this program required me to offset a lot of characters.
def offset_character(character, offset):
    if character not in string.ascii_uppercase:
        return character
    else:
        #get original index of character
        char_index = ord(character) - ord('A')
        #get offset of character. Modulate to ensure that looping around alphabet
        final_index = (char_index + offset) % 26
        #turn the integer index into the corresponding ASCII index
        return chr(final_index + ord('A'))

# Arguments: string, integer
# Returns: string
#Basically the same method as encrypt, but passing a negative offset to the offset helper method
def decrypt_caesar(ciphertext, offset):
    decrypt_offset = offset * -1
    decrypted_text = ""
    for character in ciphertext:
        decrypted_character = offset_character(character, decrypt_offset)
        decrypted_text = decrypted_text + decrypted_character
    return decrypted_text

# Vigenere Cipher
# Arguments: string, string
# Returns: string
def encrypt_vigenere(plaintext, keyword):
    plaintext_len = len(plaintext)
    keyword_len = len(keyword)
    encrypted_text = ""
    ASCII_A = ord('A')

    for i in range (0, plaintext_len):
        #looping the keyword around the plaintext string
        key_char = i % keyword_len
        offset = ord(keyword[key_char]) - ASCII_A
        #calculating amount of shift
        encrypted_text = encrypted_text + offset_character(plaintext[i], offset)
    return(encrypted_text)

# Arguments: string, string
# Returns: string
#same method as encrypt but with a negative offset value
def decrypt_vigenere(ciphertext, keyword):
    cipher_len = len(ciphertext)
    keyword_len = len(keyword)
    decrypted_text = ""
    ASCII_A = ord('A')

    for i in range (0, cipher_len):
        key_char = i % keyword_len
        offset = (ord(keyword[key_char]) - ASCII_A)*-1
        decrypted_text = decrypted_text + offset_character(ciphertext[i], offset)
    return(decrypted_text)

#generate the coprime value to Q
def gen_coprime(Q):
    #assigning starter value for R which will change later
    R = Q
    while math.gcd(R,Q) != 1:
        R = random.randint(2, Q-1)
    return R

# Merkle-Hellman Knapsack Cryptosystem
# Arguments: integer
# Returns: tuple (W, Q, R) - W a length-n tuple of integers, Q and R both integers
def generate_private_key(n=8):
    #defining an arbitrary start value for W
    W_list = [random.randint(1,15)]
    for i in range(1, n):
        #append another W value to the list
        W_list.append(random.randint(sum(W_list)+1, 2*sum(W_list)))
    Q = random.randint(sum(W_list)+1, sum(W_list)*2)
    #only passing Q to gen_coprime because haven't defined R
    R = gen_coprime(Q)
    W = tuple(W_list)
    return(W, Q, R)

# Arguments: tuple (W, Q, R) - W a length-n tuple of integers, Q and R both integers
# Returns: tuple B - a length-n tuple of integers
def create_public_key(private_key):
    #extract elements from private key
    W = private_key[0]
    Q = private_key[1]
    R = private_key[2]
    #Tuple B = tuple where B_i = R*W_i modQ
    B_list = []
    for i in range (0, len(W)):
        #add B values
        B_list.append((R * W[i]) % Q)
    B = tuple(B_list)
    #print (B)
    return(B)

# Arguments: string, tuple (W, Q, R)
# Returns: list of integers
def encrypt_mhkc(plaintext, public_key):
    bin_value_list = []
    n = 8
    A = []
    C = []
    sum = 0
    for character in plaintext:
        #for each character in the plaintext, get binary values. ensure getting 8 values.
        for binary in bin(ord(character))[2:].zfill(n):
            bin_value_list.append(int(binary))
        A.append(bin_value_list)
        #reset bin_value_list for next iteration of loop
        bin_value_list = []
    for binary_list in A:
        #multiply each binary value by the corresponding public key value
        for i in range(0, len(binary_list)):
            sum = sum + (binary_list[i] * public_key[i])
        C.append(sum)
        sum = 0
    return(C)

#calculate the S value, which is the modular inverse of R % Q
def calc_S(R,Q):
    potential_S = 1
    while ((potential_S*R) % Q != 1):
        potential_S = random.randint(2,Q)
    return potential_S

# Arguments: list of integers, tuple B - a length-n tuple of integers
# Returns: bytearray or str of plaintext
def decrypt_mhkc(ciphertext, private_key):
    W = private_key[0]
    Q = private_key[1]
    R = private_key[2]
    S = calc_S(R,Q)
    C_decipher = []
    binary_info_list = []
    decrypted = ""

    for C_value in ciphertext:
        ASCII_index = 0
        binary_information = []
        #calculate C'
        C_p = ((C_value * S) % Q)
        binary_string = ""
        #iterating backwards through W so that can find largest W value which is in the subset
        for i in range (len(W)-1, -1, -1):
            #if W[i] is part of the subset, append 1
            if C_p >= W[i]:
                #binary_information.insert(0,1)
                C_p = C_p - W[i]
                binary_string = "1" + binary_string
            #if W[i] is not part of the subset, append 0.
            elif C_p > 0:
                #binary_information.insert(0,0)
                binary_string = "0" + binary_string
            print(binary_string)
        #convert binary_string value into integer
        ASCII_index = int(binary_string, 2)
        print(chr(ASCII_index))
        #add corresponding ASCII character to decrypted string
        decrypted = decrypted + chr(ASCII_index)
    return(decrypted)

#method which tests encrypt/decrypt functions for Ceasar and Vignere
def test(csv_file, function_call):
    output = ""
    with open(csv_file, 'r') as f:
        for line in f:
            line = line.strip()
            split = line.split(',')

            if function_call == "encrypt_caesar":
                output = encrypt_caesar(split[0], int(split[1]))

            if function_call == "decrypt_caesar":
                output = decrypt_caesar(split[0], int(split[1]))

            if function_call == "encrypt_vigenere":
                output = encrypt_vigenere(split[0], split[1])

            if function_call == "decrypt_vigenere":
                output = decrypt_vigenere(split[2], split[1])

            print (split[0] == output)

def main():
    #print(encrypt_caesar("", 3))
    #test("encrypt_vigenere.csv", "decrypt_vigenere")
    #print(decrypt_caesar("", 2))
    #print(encrypt_vigenere("MANAT", "KAUR"))
    #print(decrypt_vigenere("REFCYMSEKMYZCMUEKT", "KAUR"))
    #private_key = generate_private_key()
    #public_key = create_public_key(private_key)
    #private_key = generate_private_key()
    #public_key = create_public_key(private_key)
    #encrypted = (encrypt_mhkc("Manat", public_key))
    #print(encrypted)
    #print("DECRYPTED IS " + decrypt_mhkc(encrypted, private_key))
    #decrypt_mhkc([1129], ((2,7,11,21,42,89,180,354), 881, 588))
    #decrypt_mhkc([2442, 7212, 1936, 5216, 4596, 6402, 206, 5216, 130, 6516, 4786, 826, 7212, 2632, 7022, 1936, 5216, 4596, 750, 5216, 1936, 750, 206, 4596, 2632, 636, 5216, 826, 750, 4596], ((5, 8, 18, 57, 95, 310, 903, 2290, 5423), 9341, 2))
    #print(encrypt_mhkc("MICHAELTHIBODEAUX",(18, 36, 60, 153, 411, 693, 2535, 3957)))
    #test_MHKC("MHKC_tests.csv")
    #decrypt_mhkc([2442, 7212, 1936, 5216, 4596, 6402, 206, 5216, 130, 6516, 4786, 826, 7212, 2632, 7022, 1936, 5216, 4596, 750, 5216, 1936, 750, 206, 4596, 2632, 636, 5216, 826, 750, 4596], ((5, 8, 18, 57, 95, 310, 903, 2290), 9341, 2))

    # Testing code here

if __name__ == "__main__":
    main()
