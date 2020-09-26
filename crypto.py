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
    bin_values = []
    print("Public keys, " , public_key)
    sum = 0
    A = []
    C = []
    for character in plaintext:
        #make list of binary values
        #truncate off first two characters [2:]
        bin_value = bin(ord(character))[2:]
        bin_values.append(bin_value)
    for i in bin_values:
        character_bin = i
        print(i)
        #sum = 0
        binlist_char = []
        for x in i:
            binlist_char.append(int(x))
        A.append(binlist_char)
    for i in A:
        for bins in i:
            count = 0
            sum = sum + public_key[x]*bins[i][x]
            print(sum)

        #C.append(sum(A[i][]))

'''
        print(type(i))
        integer = int(i)
        print(type(int(i)))
        for
        #print(str(i))
        #print
        #print(i)
        #integer = int(i)
        #print(integer)
        #print (int(i) for i in )

        #print (int(a) for a in i)

    #print(bin_values)

    #for i in range(0,len(bin_values)):
        #for
    #    bin = bin_values[i]

        #print(bin_values[i])
        #C.append(sum(bin_values))
        #C.append(sum(bin_values)

#     bin in bin_values:
    #    n = 0
    #    bin[n]
'''
# Arguments: list of integers, tuple B - a length-n tuple of integers
# Returns: bytearray or str of plaintext
def decrypt_mhkc(ciphertext, private_key):
    pass

def main():
    #print(encrypt_caesar("BUZZ", 2))
    #print(decrypt_caesar("DWBB", 2))
    #print(encrypt_vigenere("HELLOMYNAMEISMANAT", "KAUR"))
    #print(decrypt_vigenere("REFCYMSEKMYZCMUEKT", "KAUR"))
    private_key = generate_private_key()
    public_key = create_public_key(private_key)
    encrypt_mhkc("HELLO", public_key)

    # Testing code here
    pass

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
