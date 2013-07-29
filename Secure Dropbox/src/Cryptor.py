import CONFIG
import random
import string
import struct
import os
from Crypto.Cipher import AES
from Crypto import Random
from M2Crypto import BIO, RSA

# lambda operation to pad and unpad the AES key before de/encryption.
pad = lambda s: s + (CONFIG.BS - len(s) % CONFIG.BS) * chr(CONFIG.BS - len(s) % CONFIG.BS)
unpad = lambda s: s[0:-ord(s[-1])]

class Cryptor(object):
    '''
    Definition of cryptor instance. cryptor instance includes AES256 and RSA2048 cyrptor.
    AES is encapsulated as a file encryptor as well because most AES operation is file oriented.
    AES 256bit key generator is implemented as well. RSA key pair is not generated here but in the SecureDropbox
    instance.
    
    Attributes:
        None
    '''
    def __init__(self):
        pass

    
    def pad_AES_key(self, key):
        '''
        pad aes keys to a lenth of 32.(256bit)
        
        parameter:
            key: raw AES key to be processed.
            
        return:
            padded AES key
        '''
        if len(key) <= 32:
            for i in xrange(32 - len(key)):
                # pad aes key with character '0'
                key += '0'
        else:
            key = key[:32]

        return key
    
    def encrypt_file(self, key, in_filename, out_filename=None, chunksize=64 * 1024):
        """ Encrypts a file using AES (CBC mode) with the
            given key.

            parameter
                key:
                    The encryption key - a string that must be
                    either 16, 24 or 32 bytes long. Longer keys
                    are more secure.
    
                in_filename:
                    Name of the input file
    
                out_filename:
                    If None, '<in_filename>.enc' will be used.
    
                chunksize:
                    Sets the size of the chunk which the function
                    uses to read and encrypt the file. Larger chunk
                    sizes can be faster for some files and machines.
                    chunksize must be divisible by 16.
        """
        if not out_filename:
            out_filename = in_filename + '.enc'

        iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
        # generate AES encryptor
        encryptor = AES.new(key, AES.MODE_CBC, iv)
        filesize = os.path.getsize(in_filename)

        # encrypt block by block.
        with open(in_filename, 'rb') as infile:
            with open(out_filename, 'wb') as outfile:
                outfile.write(struct.pack('<Q', filesize))
                outfile.write(iv)

                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk += ' ' * (16 - len(chunk) % 16)

                    outfile.write(encryptor.encrypt(chunk))

    def decrypt_file(self, key, in_filename, out_filename=None, chunksize=24 * 1024):
        """ Decrypts a file using AES (CBC mode) with the
            given key. Parameters are similar to encrypt_file,
            with one difference: out_filename, if not supplied
            will be in_filename without its last extension
            (i.e. if in_filename is 'aaa.zip.enc' then
            out_filename will be 'aaa.zip')
            
             parameter
                key:
                    The encryption key - a string that must be
                    either 16, 24 or 32 bytes long. Longer keys
                    are more secure.
    
                in_filename:
                    Name of the input file
    
                out_filename:
                    If None, '<in_filename>.enc' will be used.
    
                chunksize:
                    Sets the size of the chunk which the function
                    uses to read and encrypt the file. Larger chunk
                    sizes can be faster for some files and machines.
                    chunksize must be divisible by 16.
        """
        if not out_filename:
            out_filename = os.path.splitext(in_filename)[0]

        with open(in_filename, 'rb') as infile:
            origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
            iv = infile.read(16)
        
            # generate AES decryptor
            decryptor = AES.new(key, AES.MODE_CBC, iv)
            
            # decrypt cipher block by block
            with open(out_filename, 'wb') as outfile:
                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break
                    outfile.write(decryptor.decrypt(chunk))

                outfile.truncate(origsize)

    def RSA_encryptor(self, plaintext, RSA_public_key):
        '''
            RSA encryption algorithm.
            
            parameter
                plaintext: plaintext to be cipher
                RSA_public_key: RSA public key in string
                
            return
                hex encoded RSA cipher
        '''
        
        # read string RSA pub key into memory as bio
        bio = BIO.MemoryBuffer(RSA_public_key.encode('ascii'))
        
        # generate RSA encryptor with this bio 
        rsa = RSA.load_pub_key_bio(bio)
         
        # encrypt
        encrypted = rsa.public_encrypt(plaintext, RSA.pkcs1_padding)
        return encrypted.encode('hex')

    def RSA_decryptor(self, cipher, RSA_private_key):

        '''
            RSA decryption algorithm.
            
            parameter
                cipher: cipher to be decipher
                RSA_private_key: RSA private key in string
                
            return
                hex encoded RSA plain text
        '''
        # read string RSA private key into memory as bio
        bio = BIO.MemoryBuffer(RSA_private_key.encode('ascii')) 
        
        # generate RSA decryptor with this bio        
        rsa = RSA.load_key_bio(bio)
        
        # decrypt
        decrypted = rsa.private_decrypt(cipher.decode('hex'), RSA.pkcs1_padding)

        return decrypted

    def AES_encryptor(self, plaintext, key):

        """
        Returns hex encoded encrypted value!
        
        parameter:
            plaintext: plaintext to be cipher
            key: AES 256 KEY
            
        return:
            hex encoded cipher
        """
        plaintext = pad(plaintext)
        iv = Random.new().read(AES.block_size)
        cryptor = AES.new(key, AES.MODE_CBC, iv)
        return (iv + cryptor.encrypt(plaintext)).encode("hex")

    def AES_decryptor(self, cipher, key):

        """
        Requires hex encoded param to decrypt
        
        parameter:
            cipher: cipher to be decipher
            key: AES 256 KEY
            
        return:
            unpadded plaintext
        """

        cipher = cipher.decode("hex")
        iv = cipher[:16]
        cipher = cipher[16:]
        cryptor = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cryptor.decrypt(cipher))

    def generate_new_doc_key(self):
        '''
            generate AES 256 doc key
            
            return: random generated AES 256 key
                
        '''
        
        # using random method as key generator seed
        return ''.join([(string.ascii_letters + string.digits)[x] for x in random.sample(range(0, 62), 32)])
