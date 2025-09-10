import string
import random

#Generate key and randomly map the shuffled letter with the original letters
def generate_key():
    letters = list(string.ascii_lowercase)
    shuffled = letters[:]
    random.shuffle(shuffled)
    return dict(zip(letters, shuffled))

#Encrytion function
def encrypt(plaintext, key):
    ciphertext = ""
    for char in plaintext.lower():
        if char in key:
            ciphertext += key[char]
        else:
            ciphertext += char #anything other than the key (spaces, punctuations) don't change
    return ciphertext
    
def decrypt(ciphertext, key):
    plaintext = ""
    reverse_key = {v:k for k,v in key.items()}
    for char in ciphertext.lower():
        if char in reverse_key:
            plaintext += reverse_key[char]
        else:
            plaintext += char
    return plaintext

               
if __name__ == "__main__":
    key = generate_key()
    print("Generated key: ", key)

    message = "hello, this is a secret message"
    print("Plaintext: ", message)

    #Check letter-key mapping
    encrypted = encrypt(message, key)
    print("Encrypted: ", encrypted)


    decrypted = decrypt(encrypted, key)
    print("Decrypted: ", decrypted)
