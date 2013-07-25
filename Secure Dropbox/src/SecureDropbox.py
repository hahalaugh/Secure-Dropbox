import os
import sys
import logging
import pickle
from Dropbox import DropboxHandler
from KMS import KMS_Handler
from Cryptor import Cryptor
from pbkdf2 import PBKDF2
import CONFIG
import time
import urllib2
import M2Crypto
import binascii

class SecureDropbox(object):
    def __init__(self, username, password, dropbox_folder_path):
        self.user = User(username, password)
        self.dropbox_handler = None
        self.KMS_handler = None
        self.cryptor = None
        self.dropbox_folder_path = dropbox_folder_path
        self.secure_dropbox_folder_path = self.dropbox_folder_path + r'\Secure Dropbox'
        
        if not os.path.isdir(self.secure_dropbox_folder_path):
            os.mkdir(self.secure_dropbox_folder_path)
        
        self.ini_file = self.secure_dropbox_folder_path + os.path.sep + self.user.username + CONFIG.INI_FILE

    def generate_pickle_key(self):
        salt = '12345678'  # 64-bit salt
        key = PBKDF2(self.user.password, salt).read(32)  # 256-bit key
        return key
    
    def encrypt_ini(self):
        pickle_key = self.generate_pickle_key()
        self.cryptor.encrypt_file(pickle_key, self.ini_file, self.ini_file + '.enc')
        os.remove(self.ini_file)
        os.rename(self.ini_file + '.enc', self.ini_file)
        
    def decrypt_ini(self):
        pickle_key = self.generate_pickle_key()
        self.cryptor.decrypt_file(pickle_key, self.ini_file, self.ini_file + '.dec')
        os.remove(self.ini_file)
        os.rename(self.ini_file + '.dec', self.ini_file)
        
    def initialize(self):

        self.dropbox_handler = DropboxHandler()
        self.cryptor = Cryptor()
        self.KMS_handler = KMS_Handler(self.cryptor)
        if self.login():
            
            # Only one user existing in the system at one time. Delete other user's configuration file.    
            filenames = os.listdir(self.secure_dropbox_folder_path)
            for element in filenames:
                if str(element).endswith('.ini') and self.user.username not in str(element):
                    os.remove(self.secure_dropbox_folder_path + os.path.sep + element)
            
            with open(self.ini_file, 'w') as ini_file:
                pickle.dump(self.user, ini_file, True)
            
            self.encrypt_ini()
            return True
        else:
            print ("login failed. Unauthorized user or Server not available")
            return False

    def share_file(self, user_to_share_with, file_to_share):

        sharing_info = self.dropbox_handler.client.media(self.path_local_2_dropbox(file_to_share))

        url = sharing_info['url']
        expires = sharing_info['expires']
        doc_id = os.path.basename(file_to_share)

        response = self.KMS_handler.download_sharing_recipient_RSA_pub_key(self.user.username, self.user.password, self.user.token, user_to_share_with)
        receipient_RSA_pub_key = response.read()
        
        if receipient_RSA_pub_key == CONFIG.FETCH_PUBLIC_KEY_FAILED:
            return False

        if receipient_RSA_pub_key:
            doc_key = self.cryptor.RSA_encryptor(self.user.doc_keychain[doc_id], receipient_RSA_pub_key)
        else:
            doc_key = None

        if doc_key:
            return self.KMS_handler.share_file(self.user.username, self.user.password, self.user.token, user_to_share_with, doc_id, doc_key, url, expires)
        else:
            return False
    def shared_file(self):
        return self.KMS_handler.shared_file(self.user.username, self.user.password, self.user.token)

    def login(self):
        self.user.token, self.user.RSA_pub_key, self.user.RSA_priv_key, self.user.doc_keychain = \
            self.KMS_handler.login(self.user.username, self.user.password)

        if self.user.token and self.user.token != CONFIG.INVALID_USER_INCORRECT_INFO:
            # if valid user then decrypt the encrypted RSA private key with user's password through pbkdf2
            
            print self.user.RSA_priv_key
            
            self.user.RSA_priv_key = \
             self.cryptor.AES_decryptor(self.user.RSA_priv_key, self.cryptor.pad_AES_key(self.user.password))
             
            # decrypt the doc_keys with RSA private key
            print self.user.doc_keychain
            if len(self.user.doc_keychain) != 0:
                for key in self.user.doc_keychain.keys():
                    self.user.doc_keychain[key] = \
                        self.cryptor.RSA_decryptor(self.user.doc_keychain[key], self.user.RSA_priv_key)
            return True
        else:
            return False

    def register(self, username, password):
        
        private_key_path = '%s_priv.pem' % (username)
        f = open(private_key_path, 'w')
        f.close()
        public_key_path = '%s_pub.pem' % (username)
        f = open(public_key_path, 'w')
        f.close()
        
        print 'register :: generating RSA keys...'
        M2Crypto.Rand.rand_seed (os.urandom (1024))
        RSA_key = M2Crypto.RSA.gen_key (1024, 65537)
        RSA_key.save_key (private_key_path, None)
        RSA_key.save_pub_key (public_key_path)
        
        f = open(public_key_path)
        RSA_public_key = f.read()
        f.close()
        os.remove(public_key_path)
        
        f = open(private_key_path)
        RSA_private_key = f.read()
        f.close()
        os.remove(private_key_path)
        
        RSA_private_key = self.cryptor.AES_encryptor(RSA_private_key, self.cryptor.pad_AES_key(password))
        
        return self.KMS_handler.register(username, password, RSA_public_key, RSA_private_key)

    def show_file_list(self):

        file_list = []
        serial_number = 1
        
        local_file_list = os.listdir(self.secure_dropbox_folder_path)
        KMS_file_list = \
            self.KMS_handler.download_doc_keychain(self.user.username, self.user.password, self.user.token)\
                .keys()

        for filename in local_file_list:
            if self.user.username in filename and str(filename).endswith('.enc'): 
                modification_time = \
                    time.ctime(os.stat(self.secure_dropbox_folder_path + os.path.sep + filename).st_mtime)
    
                if filename in KMS_file_list:
                    sync_state = 'sync'
                else:
                    sync_state = 'out-sync'
    
                file_list_node = [str(serial_number), filename, modification_time, sync_state]
                file_list.append(file_list_node)

                serial_number += 1
        return file_list

    def delete_file(self, file_to_delete):
        file_path = file_to_delete
        print file_path
        doc_id = os.path.basename(file_to_delete)
        print "doc_id: %s" % doc_id
        res = self.KMS_handler.delete_doc_keychain(self.user.username, self.user.password, self.user.token, doc_id).read()
        print res
        if res == CONFIG.DELETE_KEY_SUCCEED:
            try:
                os.remove(file_path)
            except OSError as e:  # name the Exception `e`
                print "Failed with:", e.strerror  # look what it says
                print "Error code:", e.code 
            return True
        else:
            return False

    def generate_doc_id(self, file_path):
        # test.txt_hahalaugh@gmail.com.enc
        doc_id = os.path.basename(file_path) + '_' + self.user.username + '.enc'
        return doc_id

    def read_file(self, file_to_read):
        doc_id = os.path.basename(file_to_read)
        doc_key = self.user.doc_keychain[doc_id]

        temp_file_path = self.secure_dropbox_folder_path + os.path.sep + str(time.time())

        self.cryptor.decrypt_file(doc_key, file_to_read, temp_file_path)

        with open(temp_file_path) as f:
            result = f.read()

        os.remove(temp_file_path)
        return result

    def load_file_into_secure_dropbox(self, file_to_load):

        doc_id = self.generate_doc_id(file_to_load)
        doc_key = self.cryptor.generate_new_doc_key()

        # encrypt the file with doc key
        target_file = self.secure_dropbox_folder_path + os.path.sep + doc_id
        self.cryptor.encrypt_file(doc_key, file_to_load, target_file)

        # encrypt the doc key with RSA public key before uploading to KMS
        print self.user.RSA_pub_key
        doc_key = self.cryptor.RSA_encryptor(doc_key, self.user.RSA_pub_key)

        upload_result = self.KMS_handler.upload_doc_key(self.user.username, self.user.password, self.user.token, doc_id, doc_key)
        print upload_result
        self.user.doc_keychain = self.KMS_handler.update_doc_keychain(self.user.username, self.user.password, self.user.token)

        print self.user.RSA_priv_key
        for key in self.user.doc_keychain.keys():
            self.user.doc_keychain[key] = \
                self.cryptor.RSA_decryptor(self.user.doc_keychain[key], self.user.RSA_priv_key)

        return upload_result

    def path_local_2_dropbox(self, local_path):
        dropbox_path = '/Secure Dropbox/' + os.path.basename(local_path)
        return dropbox_path

    def read_shared_file(self, doc_key, url):
        raw_doc_key = self.cryptor.RSA_decryptor(doc_key, self.user.RSA_priv_key)
        
        encrypted_doc_content = urllib2.urlopen(url).read()
        encrypted_doc_content.replace(binascii.a2b_hex('0d0a') , binascii.a2b_hex('0a'))
        
        temp_enc_file_path = str(time.time())
        
        f = open(temp_enc_file_path, 'wb')
        f.write(encrypted_doc_content)
        f.close()
        
        temp_file_path = self.secure_dropbox_folder_path + os.path.sep + str(time.time()) + '.enc'

        print raw_doc_key
        self.cryptor.decrypt_file(raw_doc_key, temp_enc_file_path, temp_file_path)

        with open(temp_file_path) as f:
            result = f.read()

        # os.remove(temp_file_path)
        # os.remove(temp_enc_file_path)
        return result

         
        # return self.cryptor.AES_decryptor(encrypted_doc_content, self.cryptor.pad_AES_key(raw_doc_key))

    
class User(object):
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.token = None
        self.RSA_pub_key = None
        self.RSA_priv_key = None
        self.doc_keychain = None
