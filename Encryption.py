'''
#testing to see if these were installed correctly
try:
    from cryptography.fernet import Fernet
    print("Cryptography package installed successfully")
    
    import Crypto
    print("PyCryptodome installed successfully")
    
    import cryptocode
    print("Cryptocode installed successfully")
    
    from simplecrypt import encrypt, decrypt
    print("Simplecrypt installed successfully")
except ImportError as e:
    print(f"Import error: {e}")
'''
from cryptography.fernet import Fernet
import os
from Crypto.Random import *
from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import AES
import io 

def generate_a_key():
    if os.path.exists("secret.key"):
        with open("secret.key", "wb") as filekey:  # Save the key to a file
            filekey.write(key)
    else:
        key = Fernet.generate_key()
        print("Generated key:", {key})

def load_key():
    return open("secret.key", "rb").read()

def encrypt_message(msg):
    generate_a_key()
    key = load_key()
    encoded_msg = msg.encode()
    fkey = Fernet(key)
    encrypted_msg = fkey.encrypt(encoded_msg)
    return encrypted_msg

def decrypt_message(msg):
    """Decrypt an encrypted message"""
    key = load_key()
    fkey = Fernet(key)
    decrypted_msg = fkey.decrypt(msg)
    return decrypted_msg.decode()

def aes_encrypt():
    input_file = 'plaintextFile.txt'
    output_file = 'encrypted.txt'
    file_read = open(input_file, 'rb')
    file_write = open(output_file,'wb')
    salt = get_random_bytes(32) #salt to avoid rainbow tables
    sample_pass = "samplePass12345"
    key_length = 32
    N= 2**17 #set to <0.1s could use 2**20 if anything (<5seconds)
    key = scrypt(sample_pass,salt,key_length, N, r=8, p=1) # r is block size and p is parallelization parameter
    file_write.write(salt) #remember what the salt is

    aes_cipher = AES.new(key, AES.MODE_GCM)
    file_write.write(aes_cipher.nonce) #remember nonce used
    data=file_read.read(1024*1024)
    while len(data)!=0:
        encrypted_data=aes_cipher.encrypt(data)
        file_write.write(encrypted_data)
        data = file_read.read(1024*1024)
    tag = aes_cipher.digest() #we done
    file_write.write(tag)
    file_read.close()
    file_write.close()

def aes_decrypt():
    input_file = 'encrypted.txt'
    output_file = 'decrypted.txt'
    file_read = open(input_file, 'rb')
    file_write = open(output_file,'wb')
    salt = file_read.read(32)#read salt that we wrote
    sample_pass = "samplePass12345"
    key_length = 32
    N= 2**17 #set to <0.1s could use 2**20 if anything (<5seconds)
    key = scrypt(sample_pass,salt,key_length, N, r=8, p=1) # r is block size and p is parallelization parameter
    nonce = file_read.read(16) #read nonce we wrote to file
    aes_cipher = AES.new(key, AES.MODE_GCM, nonce)

    file_read_size = os.path.getsize(input_file)
    encrypted_data_size = file_read_size - 32 - 16 - 16 #total data - (salt, nonce and tag) 
    buffer=1024*1024
    for x in range(int(encrypted_data_size/buffer)):
        data = file_read.read(buffer)
        decrypted_msg = aes_cipher.decrypt(data)
        file_write.write(decrypted_msg)
    #decrypted data has been written to output file 
    data  = file_read.read(int(encrypted_data_size % buffer)) #read leftover total data - salt - nonce - tag from earlier
    decrypted_msg = aes_cipher.decrypt(data)
    file_write.write(decrypted_msg)

    tag = file_read.read(16) #get tag and verify
    try:
        aes_cipher.verify(tag)
    except ValueError as e:
        file_write.close()
        file_read.close()
        os.remove(output_file)
        raise e
    file_write.close()
    file_read.close()


   

if __name__ == "__main__":

 '''
#test out fernet encryption & decryption
    secret = "This is a top-secret message"
    encrypt_msg = encrypt_message(secret)
    print("Encrypted message:", encrypt_msg)
    decrypt_msg = decrypt_message(encrypt_msg)
    print("Decrypted message:", decrypt_msg)
'''
#test AES Galois Counter Mode encryption and decryption
aes_encrypt()
aes_decrypt()