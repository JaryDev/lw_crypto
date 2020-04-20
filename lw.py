# importing the required modules 
import timeit 
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import json
from memory_profiler import memory_usage
from memory_profiler import profile
from xtea import *
from random import randint
import speck


# Memory Profile Log
#f=open('Mem_Log.txt','w+')

### AES ###
def aes_128_128(data, key, iv): 
    # Has a fixed data block size of 16 bytes (128 bits)
    #data = b"Where is a United states Flag that is never raised or lowered, flies 24 hours a day, seven days a week, yet it is never saluted?" # 128 bytes * 8 = 1024 bits 
    #key = get_random_bytes(16) # 16 bytes * 8 = 128 bits (1 byte = 8 bits)
    #iv = get_random_bytes(16) # It is as long as the block size

    # Encrypt
    cipher = AES.new(key, AES.MODE_CBC, iv) # Create a AES cipher object with the key using the mode CBC
    cipher_text = aes_encrypt(cipher, data)

    # Memusage of aes_encrypt
    memusage_encrypt = memory_usage((aes_encrypt, (cipher,data)))
    print('Memory consumption (in MB) of aes_encrypt', memusage_encrypt)

    # Print cipher text & iv in json base 64
    b64_cipher_text = b64encode(cipher_text).decode('utf-8')
    b64_iv = b64encode(cipher.iv).decode('utf-8')
    b64_key = b64encode(cipher.iv).decode('utf-8')
    result = json.dumps({'iv':b64_iv, 'ciphertext':b64_cipher_text})
    #print(result,'\n')

    # Decrypt
    iv = b64decode(b64_iv)
    cipher_text = b64decode(b64_cipher_text)
    cipher = AES.new(key, AES.MODE_CBC, iv) # Create a new cipher object
    plaintext = aes_decrypt(cipher, cipher_text)


    # Memusage of aes_decrypt
    memusage_decrypt = memory_usage((aes_decrypt, (cipher,cipher_text)))
    print('Memory consumption (in MB) of aes_decrypt', memusage_decrypt)

    # Print decrypted cipher text
    #print(plaintext, '\n')
  

#@profile(stream=f)
# Use $ python -m memory_profiler example.py to memory profile a function
def aes_encrypt(cipher, data): 
    cipher_text = cipher.encrypt(pad(data, AES.block_size)) # Pad the input data and then encrypt
    return cipher_text

#@profile(stream=f)
def aes_decrypt(cipher, cipher_text):
    plain_text = unpad(cipher.decrypt(cipher_text), AES.block_size)
    return plain_text


# compute AES encryption time 
def aes_encrypt_time(data, key, iv): 
    SETUP_CODE = ''' 

cipher = AES.new(key, AES.MODE_CBC, iv) '''
  
    TEST_CODE = ''' 
cipher.encrypt(pad(data, AES.block_size))'''
      
    # timeit.repeat statement 
    times = timeit.repeat(setup = SETUP_CODE, 
                          stmt = TEST_CODE, 
                          repeat = 10, 
                          number = 1, 
                          globals=globals()) 
  
    # priniting minimum exec. time 
    print('AES_Encryption Time: {}'.format(min(times)))         
  

# compute AES encryption time 
def aes_decrypt_time(data, key, iv): 
    SETUP_CODE = ''' 
#Encrypt
cipher = AES.new(key, AES.MODE_CBC, iv)
cipher_text = cipher.encrypt(pad(data, AES.block_size)) 

# Setup object to decrypt
cipher = AES.new(key, AES.MODE_CBC, iv) # Create a new cipher object'''

  
    TEST_CODE = ''' 
unpad(cipher.decrypt(cipher_text), AES.block_size)'''
      
    # timeit.repeat statement 
    times = timeit.repeat(setup = SETUP_CODE, 
                          stmt = TEST_CODE, 
                          repeat = 10, 
                          number = 1, 
                          globals=globals()) 
  
    # priniting minimum exec. time 
    print('AES_Decryption Time: {}'.format(min(times)))         
  





  
### XTEA ###
def xtea_64_128(data, key, iv):

    # NOTE: IV must be be 8 bytes (64-bits) , same as the block size
    x = new(key, mode=MODE_CBC, IV=iv) # Create a new cipher object

    #data = b"This is a text. "*64

    cipher_text = x.encrypt(data)
    #print(cipher_text)

    plaintext = x.decrypt(cipher_text)
    #print(plaintext)



    # Memusage of XTEA_encrypt
    memusage_encrypt = memory_usage((xtea_encrypt, (x, data)))
    print('Memory consumption (in MB) of XTEA_encrypt', memusage_encrypt)
    # Memusage of XTEA_decrypt
    memusage_decrypt = memory_usage((xtea_decrypt, (x, data)))
    print('Memory consumption (in MB) of XTEA_decrypt', memusage_decrypt)





def xtea_encrypt(cipher, data):
    cipher.encrypt(data)

def xtea_decrypt(cipher, data):
    cipher.decrypt(data)



# compute XTEA encryption time 
def XTEA_encrypt_time(data, key, iv): 
    SETUP_CODE = ''' 
x = new(key, mode=MODE_CBC, IV=iv[:8])'''
  
    TEST_CODE = ''' 
x.encrypt(data)'''
      
    # timeit.repeat statement 
    times = timeit.repeat(setup = SETUP_CODE, 
                          stmt = TEST_CODE, 
                          repeat = 10, 
                          number = 1, 
                          globals=globals()) 
  
    # priniting minimum exec. time 
    print('XTEA_Encryption Time: {}'.format(min(times)))        


# compute XTEA decryption time 
def XTEA_decrypt_time(data, key, iv): 
    SETUP_CODE = ''' 
x = new(key, mode=MODE_CBC, IV=iv[:8])
cipher_text = x.encrypt(data)'''
  
    TEST_CODE = ''' 
x.decrypt(cipher_text)'''
      
    # timeit.repeat statement 
    times = timeit.repeat(setup = SETUP_CODE, 
                          stmt = TEST_CODE, 
                          repeat = 10, 
                          number = 1, 
                          globals=globals()) 
  
    # priniting minimum exec. time 
    print('XTEA_Decryption Time: {}'.format(min(times)))        




def SPECK_128_128(plaintext, key, iv):

    s = speck.Python_SPECK(key, iv)

    ciphertext = s.encrypt(plaintext)
    #print("Cipher Block:%s"%ciphertext)

    s2 =  speck.Python_SPECK(key, iv)
    Recovered_plaintext=s2.decrypt(ciphertext)
    #print("Decrypted Cipher Block: %s"%Recovered_plaintext)



    # Memusage of SPECK_128_128_encrypt
    memusage_encrypt = memory_usage((speck_encrypt, (s, plaintext)))
    print('Memory consumption (in MB) of SPECK_128_128_encrypt', memusage_encrypt)
    # Memusage of SPECK_128_128_decrypt
    memusage_decrypt = memory_usage((speck_decrypt, (s2, plaintext)))
    print('Memory consumption (in MB) of SPECK_128_128_decrypt', memusage_decrypt)


def speck_encrypt(cipher, plaintext):
    cipher.encrypt(plaintext)

def speck_decrypt(cipher, plaintext):
    cipher.decrypt(plaintext)



# compute SPECK encryption time 
def SPECK_encrypt_time(data, key, iv): 
    SETUP_CODE = ''' 
s = speck.Python_SPECK(key, iv)
plaintext = list(data)'''
  
    TEST_CODE = ''' 
s.encrypt(plaintext)'''
      
    # timeit.repeat statement 
    times = timeit.repeat(setup = SETUP_CODE, 
                          stmt = TEST_CODE, 
                          repeat = 10, 
                          number = 1, 
                          globals=globals()) 
  
    # priniting minimum exec. time 
    print('SPECK_Encryption Time: {}'.format(min(times)))        


# compute SPECK decryption time 
def SPECK_decrypt_time(data, key, iv): 
    SETUP_CODE = ''' 
s = speck.Python_SPECK(key, iv)
plaintext = list(data)
ciphertext = s.encrypt(plaintext)

s2 =  speck.Python_SPECK(key, iv)
'''
  
    TEST_CODE = ''' 
s2.decrypt(ciphertext)'''
      
    # timeit.repeat statement 
    times = timeit.repeat(setup = SETUP_CODE, 
                          stmt = TEST_CODE, 
                          repeat = 10, 
                          number = 1, 
                          globals=globals()) 
  
    # priniting minimum exec. time 
    print('SPECK_Decryption Time: {}'.format(min(times)))      



if __name__ == "__main__": 


    pBytes = [16, 1024, 102400, 1048576, 10485760]

    for i in pBytes:
        # Input
        data = get_random_bytes(i)
        #data = b"Where is a United states Flag that is never raised or lowered, flies 24 hours a day, seven days a week, yet it is never saluted?" # 128 bytes * 8 = 1024 bits 
        key = get_random_bytes(16) # 16 bytes * 8 = 128 bits (1 byte = 8 bits)
        iv = get_random_bytes(16) # It is as long as the block size

        print("\nPlainttext size in bytes = ", len(data))

        print("\nBenchmark Tests for AES_128_128")
        aes_128_128(data, key, iv) # produces memory usage values. 
        aes_encrypt_time(data, key, iv)
        aes_decrypt_time(data, key, iv)
        
        print("\nBenchmark Tests for XTEA_64_128")
        xtea_64_128(data, key, iv[:8]) # produces memory usage values. 
        XTEA_encrypt_time(data, key, iv)
        XTEA_decrypt_time(data, key, iv)

        print("\nBenchmark Tests for SPECK_128_128")
        SPECK_128_128(list(data), key, iv) # Produces memory usage values
        SPECK_encrypt_time(data, key, iv)
        SPECK_decrypt_time(data, key, iv)
