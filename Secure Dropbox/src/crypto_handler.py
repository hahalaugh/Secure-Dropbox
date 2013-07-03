#coding:utf8

import M2Crypto
from M2Crypto import BIO, RSA

from base64 import b64encode, b64decode

ENC=1
DEC=0

SHA_ITERATION = 1000

KEY_LEN = 32
PADDING = M2Crypto.RSA.no_padding

class CryptoHandler(object):
    
    def __init__(self):
        pass
    
    def AES_build_cipher(self, key, iv, op=ENC):
        return M2Crypto.EVP.Cipher(alg='aes_256_cbc', key=key, iv=iv, op=op)
    
    
    def AES_encryptor(self, key, plaintext, iv=None):
        """"""
        #Decode the key and iv
        key = b64decode(key)
        if iv is None:
            iv = '\0' * 16
        else:
            iv = b64decode(iv)  
    
        # Return the encryption function
        def encrypt(data):
            cipher = self.AES_build_cipher(key, iv, ENC)
            v = cipher.update(data)
            v = v + cipher.final()
            del cipher
            v = b64encode(v)
            return v
        print "AES encryption successful\n"
        return encrypt(plaintext)
    
    
    def AES_decryptor(self, key, ciphertext, iv=None):
        """"""
        #Decode the key and iv
        key = b64decode(key)
        if iv is None:
            iv = '\0' * 16
        else:
            iv = b64decode(iv)
    
        # Return the decryption function
        def decrypt(data):
            data = b64decode(data)
            cipher = self.AES_build_cipher(key, iv, DEC)
            v = cipher.update(data)
            v = v + cipher.final()
            del cipher
            return v
        print "AES decryption successful\n"
        return decrypt(ciphertext)

    def generate_hashed_password(self, salt, plaintext_password):
        return M2Crypto.EVP.pbkdf2(plaintext_password, salt, iter = SHA_ITERATION, keylen = KEY_LEN)
    
    def AES_file_encryptor(self, file_path, key):
        
        file_handler = open(file_path)
        text = file_handler.read()
        file_handler.close()
        encrypted_msg = self.AES_encryptor(b64encode(key),b64encode(text))
        
        file_handler = open(file_path, 'w')
        file_handler.write(encrypted_msg)
        file_handler.close()
    
    def AES_file_decryptor(self, file_path, key):
        
        file_handler = open(file_path)
        text = file_handler.read()
        file_handler.close()
        decrypted_msg = b64decode(self.AES_decryptor(b64encode(key),text))
        
        file_handler = open(file_path, 'w')
        file_handler.write(decrypted_msg)
        file_handler.close()

    def RSA_read_key(self, filename):
        try:
            key = open(filename).read()
        except IOError:
            #key = urllib2.urlopen('http://svn.osafoundation.org/m2crypto/trunk/tests/' + filename).read()
            #if there is no file found locally, fetch it from server.
            #TOBEDONE
            open(filename, 'w').write(key)
        return key
    
    def RSA_encryptor(self, message, key):
        
        bio = BIO.MemoryBuffer(key)
        rsa = RSA.load_pub_key_bio(bio)
        
        # encrypt
        encrypted = rsa.public_encrypt(message, RSA.pkcs1_padding)
        return encrypted.encode('base64')
    
    def RSA_decryptor(self, message, key):
        
        rsa = RSA.load_key_string(key)
        decrypted = rsa.private_decrypt(message, RSA.pkcs1_padding)
        
        return decrypted.encode('base64') 


if __name__ == '__main__':
    file_path = 'C:\\Users\\jjMM\\Desktop\\test.txt'
    #salt = os.urandom(32)
    salt = '1234'
    c = CryptoHandler()
    key = c.generate_hashed_password(salt, 'hahalaugh')
    #c.AES_file_encryptor(file_path, key)
    c.AES_file_decryptor(file_path, key)
    
    key = c.RSA_read_key('pub_key.pem')
    message = 'hahalaugh'
    c.RSA_encryptor(message, key)

