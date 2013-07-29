import os
import CONFIG
from Cryptor import Cryptor
import pickle
import time
import traceback
from pbkdf2 import PBKDF2
import sys

class SecureDropboxLocal(object):
    '''
    Secure Dropbox Local mode. When there is no Internet access, SecureDropbox would be switched to local mode.
    Under local mode, operation is quite limited and user can only read existed files. Doc key chain is from local ini
    file that generated when login in regular mode.
    
    Attributes:
        cryptor: None in constructor but initialized in other initialization method
        user: A User type instance.
        dropbox_folder_path: auto detected in the file system. Please insure there is no folder with same name
            in your file system. It will leads to the encrypted file is load into a regular local folder so no synchronization
            operation would be done by Dropbox client which will dramatically impact the file sharing with other user
            and multi-client mechanism since there is no file actually synchronized to the cloud.
        secure_dropbox_folder_path: located in dropbox_folder_path. The only folder that SecureDropbox would do with.
        ini_file: ini_file include a pickle instance of user. It's generated based on the fetched kms information when login
            previously. 
    '''
    def __init__(self, username, password, dropbox_folder_path):
        '''
            initialize the SecureDropboxLocal instance
            
            parameter:
                username: username to login
                password: password to login
                dropbox_folder_path: auto detected dropbox client path
                
            return:
                None
        '''
        self.user = User(username, password)
        self.dropbox_folder_path = dropbox_folder_path
        # no cryptor here.
        self.cryptor = None
        self.secure_dropbox_folder_path = self.dropbox_folder_path + r'\Secure Dropbox'
        self.ini_file = self.secure_dropbox_folder_path + os.path.sep + self.user.username + CONFIG.INI_FILE

    def read_ini(self):
        '''
        read the ini_file. ini_file is encrypted so if decrypt with incorrect password(which indicates an unauthorized
        user is try to login), the ini_file would not be deciphered correctly so no useful content will
        be discovered. Only under local mode this ini_file would be read while only under regular mode the ini_file would be generated.
        
        parameter:
            None
            
        return
            user instance from ini_file.
        '''
        # generate a pickle based on user's password. if password is not a valid one then decipher is not
        # correctly performed.
        pickle_key = self.generate_pickle_key()
        
        # decrypt ini_file with pickle_key. a user instance is stored encryptedly inside ini_file.
        self.cryptor.decrypt_file(pickle_key, self.ini_file, self.ini_file + '.dec')
        
        # get the user instance
        with open(self.ini_file + '.dec', 'r') as ini_file:
            temp_user = pickle.load(ini_file)
        
        # remove temp file generating during the reading ini procedure.
        os.remove(self.ini_file + '.dec')
        
        return temp_user
        
    def generate_pickle_key(self):
        '''
            generate the AES256 key for encrypting the pickle file. 
            salt is fixed so essentially just a procedure of hash the plain password via PBKDF2 infrastructure.
            
            parameter:
                None
                
            return:
                AES256 key 
        '''
        # 64-bit fixed salt
        salt = '12345678'
        
        # hash the plain text user password and get a 256-bit AES key.
        key = PBKDF2(self.user.password, salt).read(32)
        return key
    
    def initialize(self):
        '''
        initialize the cryptor here and perform a local login procedure. 
        Login information is based on user instance in ini_file.
        
        parameter:
            None
        
        return:
            flag indicate local_login succeed or not
        '''
        # create a cryptor instance
        self.cryptor = Cryptor()
        # perform a local login procedure and return the login result flag
        return self.local_login()
    
    def local_login(self):
        '''
        perform a local login.
        parameter:
            None
        return
            flag indicate if login succeed
        '''
        
        # if there is no ini_file(which indicates no login procedure has been performed on this machine)
        # there is no user instance to be matched with so exit the programme.
        if not os.path.exists(self.ini_file):
            return False
        else:
            try:
                # get user instance in the ini_file and match user information as login. 
                temp_user = self.read_ini()
                # this is actually more than just matching the password since as long as password is not
                # the same one as used for encrypting the ini file, nothing could be achieved from ini_file
                # and this procedure wont happen.
                if self.user.username == temp_user.username and (self.user.password == temp_user.password):
                    
                    # if authorized user then grant all the user KMS info to the use.
                    self.user.RSA_pub_key = temp_user.RSA_pub_key
                    self.user.RSA_priv_key = temp_user.RSA_priv_key
                    self.user.doc_keychain = temp_user.doc_keychain     
                    return True
                else:
                    # not matched. Actually would never be reached to this code.
                    print 'login authentication failed'
                    return False
            except:
                # except caught indicate file is not decrypted properly. So it's not a valid key 
                # that is being used.
                print 'login authentication failed'
                return False
            
    def show_file_list(self):

        '''
        generate local file list to be displayed in UI.
        
        parameter:
            None
        
        return:
            file_list to be displayed in UI.
        '''
        file_list = []
        serial_number = 1
        
        # get local folder file list
        local_file_list = os.listdir(self.secure_dropbox_folder_path)

        # generating file list format to be displayed
        for filename in local_file_list:
            if self.user.username in filename and str(filename).endswith('.enc'):
                modification_time = \
                    time.ctime(os.stat(self.secure_dropbox_folder_path + os.path.sep + filename).st_mtime)
    
                file_list_node = [str(serial_number), filename, modification_time, 'unknown']
                file_list.append(file_list_node)
                serial_number += 1

        return file_list
    
    def read_file(self, file_to_read):
        '''
            read encrypted file.
            
            parameter:
                file_to_read: local encrypted file path to be read
                
            return 
                decrypted file content
        '''
        doc_id = os.path.basename(file_to_read)
        # get doc key from doc keychain.
        try:
            doc_key = self.user.doc_keychain[doc_id]
        except:
            return 'There is no doc key for this file'

        # generate temp file to store plain text
        temp_file_path = self.secure_dropbox_folder_path + os.path.sep + str(time.time())

        # decrypt the cipher doc
        self.cryptor.decrypt_file(doc_key, file_to_read, temp_file_path)

        # get file content and ready for return.
        with open(temp_file_path) as f:
            result = f.read()
        os.remove(temp_file_path)
        
        return result
    
class User(object):
    '''
    Definition of user instance. Basically it's the KMS server's mainly oriented object.
    
    Attribute:
        username: account name
        password: account password
        token: timestamp returned by KMS server.
        rsa_pub_key: RSA public key
        rsa_priv_key: RSA private key
        doc_keychain: a dictionary use doc id as key and doc key as value.
    '''
    
    def __init__(self, username, password):
        '''
        initialize the instance.
        
        only username and password is initialized. If token is -1 or None, then 
        it's not a valid user although username and password has been initialized.
        '''
        self.username = username
        self.password = password
        self.token = None
        self.RSA_pub_key = None
        self.RSA_priv_key = None
        self.doc_keychain = None
