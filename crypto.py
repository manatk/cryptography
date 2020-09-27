import string, random, math
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
        key_char = i % keyword_len
        offset = ord(keyword[key_char]) - ASCII_A
        encrypted_text = encrypted_text + offset_character(plaintext[i], offset)
    return(encrypted_text)

# Arguments: string, string
# Returns: string
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
    W_list = [random.randint(1,15)]
    for i in range(1, n+1):
        W_list.append(random.randint(sum(W_list)+1, 2*sum(W_list)))

    Q = random.randint(sum(W_list)+1, sum(W_list)*2)
    #only passing Q to gen_coprime because haven't defined R
    R = gen_coprime(Q)
    W = tuple(W_list)
    return(W, Q, R)

# Arguments: tuple (W, Q, R) - W a length-n tuple of integers, Q and R both integers
# Returns: tuple B - a length-n tuple of integers
def create_public_key(private_key):

    W = private_key[0]
    Q = private_key[1]
    R = private_key[2]
    #Tuple B = tuple where B_i = R*W_i modQ
    B_list = []

    for i in range (0, len(W)):
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
        for binary in bin(ord(character))[2:].zfill(n):
            bin_value_list.append(int(binary))
        A.append(bin_value_list)
        bin_value_list = []
    for binary_list in A:
        for i in range(0, len(binary_list)):
            sum = sum + (binary_list[i] * public_key[i])
        C.append(sum)
        sum = 0
    return(C)

def calc_S(R,Q):
    potential_S = 1
    while ((potential_S*R) % Q != 1):
        potential_S = random.randint(2,Q)
    return potential_S


# Arguments: list of integers, tuple B - a length-n tuple of integers
# Returns: bytearray or str of plaintext
def decrypt_mhkc(ciphertext, private_key):
    print (ciphertext)
    print (private_key)
    W = private_key[0]
    Q = private_key[1]
    R = private_key[2]
    S = calc_S(R,Q)
    C_decipher = []
    binary_info_list = []
    decrypted = ""

    #print(ciphertext)
    for C_value in ciphertext:
        ASCII_index = 0
        binary_information = []
        C_p = ((C_value * S) % Q)
        binary_string = ""
        #print ("C_Value ", C_Value)
        print ("C_Prime ", C_p)
        print ("Beginning BINARY_INFO", binary_information)

        #print ("S ", S)
        #print ("Q ", Q)
        #C_decipher.append(C_p)
        for i in range (len(W)-1, -1, -1):
            print ("W[i] is ", W[i], i)
            if C_p >= W[i]:
                binary_information.insert(0,1)
                C_p = C_p - W[i]
                #print ("W[i] is " , W[i])
                #print ("CP IS UPDATED ",  C_p)
                binary_string = "1" + binary_string

                #print ("W[i] is " , W[i])
            elif C_p > 0:
                #print ("CPRIME IS ", C_p)
                #print (" I IS ", i)
                binary_information.insert(0,0)
                binary_string = "0" + binary_string
            print ("BINARY_INFO", binary_information)
        #binary_info_list.append(binary_string)
        print(binary_string)
        print(binary_information)
        print(int(binary_string, 2))
        ASCII_index = int(binary_string, 2)
        #print (ASCII_index)
        decrypted = decrypted + chr(ASCII_index)
        #ASCII_index = 0

        #binary_info_list.append(binary_information)
        #print("THIS IS INT", int(binary_string, 2))
        print(decrypted)

    #print (binary_info_list)

'''
    W = private_key[0]
    Q = private_key[1]
    R = private_key[2]
    S = calc_S(R,Q)
    C_decipher = []
    binary_info_list = []

    print(ciphertext)
    for C_value in ciphertext:
        binary_information = []
        binary_string = ""
        C_p = ((C_value * S) % Q)
        print(C_value)

        print ("C_Prime ", C_p)
        print ("S ", S)
        print ("Q ", Q)
        #C_decipher.append(C_p)

        for i in range (len(W)-1, -1, -1):
            print ("CP IS ", C_p)
            if C_p >= W[i]:
                binary_information.insert(0,1)
                C_p = C_p - W[i]
                #Eprint ("BINARY_INFO", binary_information)
            else:
                binary_information.insert(0,0)
            print ("BINARY_INFO", binary_information)
        binary_info_list.append(binary_information)

'''
'''
        for i in range (len(W)-1, -1, -1):
            print ("CP ", C_p)
            if C_p >= W[i]:
                binary_information.insert(0,1)
                binary_string = "1" + binary_string
                C_p = C_p - W[i]
                #print ("BINARY_INFO", binary_information)
            elif C_p > 0:
                binary_information.insert(0,0)
                binary_string = "0" + binary_string
            print ("BINARY_INFO", binary_information)
            #print ("BINARY_STRING", binary_string)
        print("THIS IS INT", int(binary_string, 2))
        binary_info_list.append(binary_information)
'''
    #print (binary_info_list)

'''
    W = private_key[0]
    Q = private_key[1]
    R = private_key[2]
    S = calc_S(R,Q)
    C_decipher = []
    binary_info_list = []

    print(ciphertext)
    for C_value in ciphertext:
        binary_information = []
        C_p = ((C_value * S) % Q)
        print(C_value)
        binary_string = ""

        print ("C_Prime ", C_p)
        print ("S ", S)
        print ("Q ", Q)
        #C_decipher.append(C_p)

        for i in range (len(W)-1, -1, -1):
            print ("WI IS ", W[i])
            if C_p >= W[i]:
                binary_string = "1" + binary_string
                binary_information.insert(0,1)
                C_p = C_p - W[i]
                #Eprint ("BINARY_INFO", binary_information)
            else:
                binary_information.insert(0,0)
                binary_string = "0" + binary_string
        print ("BINARY_INFO", binary_string)
        print ("BINARY LIST ", binary_information)
        binary_info_list.append(binary_information)

    print (binary_info_list)

'''

def test(csv_file, function_call):
    output = ""
    with open(csv_file, 'r') as f:
        for line in f:
            line = line.strip()
            split = line.split(',')
            #print(split)

            if function_call == "encrypt_caesar":
                output = encrypt_caesar(split[0], int(split[1]))

            if function_call == "decrypt_caesar":
                output = decrypt_caesar(split[0], int(split[1]))

            if function_call == "encrypt_vigenere":
                output = encrypt_vigenere(split[0], split[1])

            if function_call == "decrypt_vigenere":
                output = decrypt_vigenere(split[2], split[1])

                print (split[0] == output)

            #if output != split[2]:
                #print("ERROR: ", output, split[0])

def test_MHKC(csv_file):
    output = ""
    with open(csv_file, 'r') as f:
        for line in f:
            line = line.strip()
            split = line.split(',')
            print(split)
            output = encrypt_mhkc(split[2], split[1])
            print(output)
            print(split[3])


'''
 print(split[2],",", split[1], ",", split[0])

    if function_call == "decrypt_caesar":
        with open(csv_file, 'r') as f:
            for line in f:
                line = line.strip()
                split = line.split(',')
                print(split)
                output = decrypt_caesar(split[0], int(split[1]))
                print (output)
                if output != split[2]:
                    print("ERROR: ", output, split[0])

    if function_call == "encrypt_vigenere":


'''

def main():
    #print(encrypt_caesar("Z", 3))
    #test("encrypt_vigenere.csv", "decrypt_vigenere")
    #print(decrypt_caesar("DWBB", 2))
    #print(encrypt_vigenere("HELLOMYNAMEISMANAT", "KAUR"))
    #print(decrypt_vigenere("REFCYMSEKMYZCMUEKT", "KAUR"))
    #private_key = generate_private_key()
    #public_key = create_public_key(private_key)
    #private_key = generate_private_key()
    #public_key = create_public_key(private_key)
    #print(encrypt_mhkc("FOREACHEPSILONGREATERTHANDELTA", public_key))
    #decrypt_mhkc([1129], ((2,7,11,21,42,89,180,354), 881, 588))
    #decrypt_mhkc([2442, 7212, 1936, 5216, 4596, 6402, 206, 5216, 130, 6516, 4786, 826, 7212, 2632, 7022, 1936, 5216, 4596, 750, 5216, 1936, 750, 206, 4596, 2632, 636, 5216, 826, 750, 4596], ((5, 8, 18, 57, 95, 310, 903, 2290, 5423), 9341, 2))
    #print(encrypt_mhkc("MICHAELTHIBODEAUX",(18, 36, 60, 153, 411, 693, 2535, 3957)))
    #test_MHKC("MHKC_tests.csv")
    decrypt_mhkc([2442, 7212, 1936, 5216, 4596, 6402, 206, 5216, 130, 6516, 4786, 826, 7212, 2632, 7022, 1936, 5216, 4596, 750, 5216, 1936, 750, 206, 4596, 2632, 636, 5216, 826, 750, 4596], ((5, 8, 18, 57, 95, 310, 903, 2290), 9341, 2))



    # Testing code here

if __name__ == "__main__":
    main()

'''
Even if you know how to encrypt something, you don't know how to decrypt it.
Using public key decryption system. Everyone participates in this system.
1/2 of key is private, 1/2 key is public.
People will use your public key to send you an encrypted message, and you will
use your private key to unlock it

If number at the end of the list is less than target, you know everything to the left
of that number must be included in the subset.

'''
