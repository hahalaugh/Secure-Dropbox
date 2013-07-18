import CONFIG
import random
import string
import struct
import os

from Crypto.Cipher import AES
from Crypto import Random
from M2Crypto import BIO, RSA

pad = lambda s: s + (CONFIG.BS - len(s) % CONFIG.BS) * chr(CONFIG.BS - len(s) % CONFIG.BS)
unpad = lambda s: s[0:-ord(s[-1])]

class Cryptor(object):
    def __init__(self):
        pass

    def pad_AES_key(self, key):
        if len(key) <= 32:
            for i in xrange(32 - len(key)):
                key += '0'
        else:
            key = key[:32]

        return key
    def encrypt_file(self, key, in_filename, out_filename=None, chunksize=64 * 1024):
        """ Encrypts a file using AES (CBC mode) with the
            given key.

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
        encryptor = AES.new(key, AES.MODE_CBC, iv)
        filesize = os.path.getsize(in_filename)

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
        """
        if not out_filename:
            out_filename = os.path.splitext(in_filename)[0]

        with open(in_filename, 'rb') as infile:
            origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
            iv = infile.read(16)
            decryptor = AES.new(key, AES.MODE_CBC, iv)

            with open(out_filename, 'wb') as outfile:
                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break
                    outfile.write(decryptor.decrypt(chunk))

                outfile.truncate(origsize)

    def RSA_encryptor(self, plaintext, RSA_public_key):

        bio = BIO.MemoryBuffer(RSA_public_key.encode('ascii')) 
        rsa = RSA.load_pub_key_bio(bio)
         
        # encrypt
        encrypted = rsa.public_encrypt(plaintext, RSA.pkcs1_padding)
        return encrypted.encode('hex')

    def RSA_decryptor(self, cipher, RSA_private_key):

        bio = BIO.MemoryBuffer(RSA_private_key.encode('ascii')) 
        rsa = RSA.load_key_bio(bio)
        
        decrypted = rsa.private_decrypt(cipher.decode('hex'), RSA.pkcs1_padding)

        return decrypted

    def AES_encryptor(self, plaintext, key):

        """
        Returns hex encoded encrypted value!
        """
        plaintext = pad(plaintext)
        iv = Random.new().read(AES.block_size)
        cryptor = AES.new(key, AES.MODE_CBC, iv)
        return (iv + cryptor.encrypt(plaintext)).encode("hex")

    def AES_decryptor(self, cipher, key):

        """
        Requires hex encoded param to decrypt
        """

        cipher = cipher.decode("hex")
        iv = cipher[:16]
        cipher = cipher[16:]
        cryptor = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cryptor.decrypt(cipher))

    def generate_new_doc_key(self):
        return ''.join([(string.ascii_letters + string.digits)[x] for x in random.sample(range(0, 62), 32)])
