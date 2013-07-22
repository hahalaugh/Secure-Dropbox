import os
import CONFIG
from Cryptor import Cryptor
import pickle
import time
import traceback
from pbkdf2 import PBKDF2

class SecureDropboxLocal(object):
    def __init__(self, username, password, dropbox_folder_path):
        self.user = User(username, password)
        self.dropbox_folder_path = dropbox_folder_path
        self.cryptor = None
        self.secure_dropbox_folder_path = self.dropbox_folder_path + r'\Secure Dropbox'
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

        self.cryptor = Cryptor()
        return self.local_login()
    
    def local_login(self):
        if not os.path.exists(self.ini_file):
            return False
        else:
            self.decrypt_ini()
            
            with open(self.ini_file, 'r') as ini_file:
                temp_user = pickle.load(ini_file)
            
            try:
                if self.user.username == temp_user.username and (self.user.password == temp_user.password):
                    self.user.RSA_pub_key = temp_user.RSA_pub_key
                    self.user.RSA_priv_key = temp_user.RSA_priv_key
                    self.user.doc_keychain = temp_user.doc_keychain
                    
                    self.encrypt_ini()
                    return True
                else:
                    return False
            except:
                print traceback.format_exc()
                return False
            
    def show_file_list(self):

        file_list = []
        serial_number = 1
        
        local_file_list = os.listdir(self.secure_dropbox_folder_path)

        for filename in local_file_list:
            if self.user.username in filename and str(filename).endswith('.enc'):
                modification_time = \
                    time.ctime(os.stat(self.secure_dropbox_folder_path + os.path.sep + filename).st_mtime)
    
                file_list_node = [str(serial_number), filename, modification_time]
                file_list.append(file_list_node)
                serial_number += 1

        return file_list
    
    def read_file(self, file_to_read):
        doc_id = os.path.basename(file_to_read)
        doc_key = self.user.doc_keychain[doc_id]

        temp_file_path = self.secure_dropbox_folder_path + os.path.sep + str(time.time())

        self.cryptor.decrypt_file(doc_key, file_to_read, temp_file_path)

        with open(temp_file_path) as f:
            result = f.read()

        os.remove(temp_file_path)
        return result
    
class User(object):
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.token = None
        self.RSA_pub_key = None
        self.RSA_priv_key = None
        self.doc_keychain = None