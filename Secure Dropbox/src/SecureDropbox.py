import os
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
    '''
    SecureDropbox is the main functional class in the application. 
    
    This module include the user control, dropbox API handler, KMS handler and a cryptor instance 
    for the everywhere usage of cryptography operations.The instance of SecureDropbox is created and 
    manipulated by SecureDropboxUI instance. It's the instance to be created when internet accessable
    
    Attributes:
        user: A User type instance.
        dropbox_handler: contains the client token get from Dropbox via OAuth. 
        KMS_handler: contains the method to call rest API of KMS server.
        cryptor: A cryptor instance include the embodiment of AES256, RSA256 and PBKDF2.
        dropbox_folder_path: auto detected in the file system. Please insure there is no folder with same name
            in your file system. It will leads to the encrypted file is load into a regular local folder so no synchronization
            operation would be done by Dropbox client which will dramatically impact the file sharing with other user
            and multi-client mechanism since there is no file actually synchronized to the cloud. 
        secure_dropbox_folder_path: located in dropbox_folder_path. The only folder that SecureDropbox would do with.
        ini_file: ini_file include a pickle instance of user. It's generated based on the fetched kms information when login
        and fetched when using the local when there is no internet access. The RSA key pair and key chains for AES are stored
        
    '''
    def __init__(self, username, password, dropbox_folder_path):
        
        '''
            initialize the SecureDropbox instance.
            
            parameter:
                username: username of potential user.
                password: accordant password of username
                dropbox_folder_path: achieved by UI instance.
                
            return:
                None
        '''
        # generate a user instance. this step is just after user inputing the login information.
        # only attributes of username and password is initialized here. Other attributes left None.
        self.user = User(username, password)
        
        # these three attributes would be initialized in the start method.
        self.dropbox_handler = None
        self.KMS_handler = None
        self.cryptor = None
        
        # declare the dropbox_folder_path and the secure_dropbox_folder_path that application will operate with.
        self.dropbox_folder_path = dropbox_folder_path
        self.secure_dropbox_folder_path = self.dropbox_folder_path + r'\Secure Dropbox'
        
        # if secure_dropbox_folder_path is not existed or not a folder, generate a new one.  
        if not os.path.isdir(self.secure_dropbox_folder_path):
            os.mkdir(self.secure_dropbox_folder_path)
        
        # specify the path. File will be created in the start method.
        self.ini_file = self.secure_dropbox_folder_path + os.path.sep + self.user.username + CONFIG.INI_FILE

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
    
    def encrypt_ini(self):
        '''
            encrypt the ini file with AES256 and pickle key
            
            parameter:
                None
                
            return:
                None 
        '''
        
        # generate the pickle_key based on user password
        pickle_key = self.generate_pickle_key()
        
        # encrypt the ini file and genearte a temp file.
        self.cryptor.encrypt_file(pickle_key, self.ini_file, self.ini_file + '.enc')
        
        # remove the temp file and rename the encrypted ini file.
        os.remove(self.ini_file)
        os.rename(self.ini_file + '.enc', self.ini_file)
        
        # uncomment this to set the ini file hidden. The default configuration allow several
        # SecureDorpbox Account using same local dropbox client folder, which is logically inappropriate.
        
        # win32api.SetFileAttributes(self.ini_file, win32con.FILE_ATTRIBUTE_HIDDEN)

    def initialize(self):
        '''
            initialize essential instances required in the SecureDropbox.
            
            parameter:
                None
                
            return:
                flag indicate the initialization succeed or not.
        '''
        
        # initialize the handlers. KMS handler needs a cryptor instance so passed as parameter to the 
        # constructor of KMS_Handler.
        self.dropbox_handler = DropboxHandler()
        self.cryptor = Cryptor()
        self.KMS_handler = KMS_Handler(self.cryptor)
        
        # self.login initialize the user information include RSA key pair and doc_key_chain if login result
        # is positive. 
        if self.login():
            
            # The very first design is only one user existing in the system at one time. 
            # Delete other user's configuration file.
            # Now the logic retain all users' ini file and allow simultaneously usage which is not logically appropriate.   
            filenames = os.listdir(self.secure_dropbox_folder_path)
            for element in filenames:
                if str(element).endswith('.ini') and self.user.username not in str(element):
                    pass
                    # uncomment this to not remove but conceal the file.
                    # os.remove(self.secure_dropbox_folder_path + os.path.sep + element)
            
            # dump the user instance into ini_file
            with open(self.ini_file, 'w') as ini_file:
                pickle.dump(self.user, ini_file, True)
            
            # encrypt the ini_file
            self.encrypt_ini()
            
            return True
        else:
            
            # login failed
            print ("login failed. Unauthorized user or Server not available")
            
            return False

    def share_file(self, user_to_share_with, file_to_share):

        '''
        share the file with specified user.
        
        parameters:
            user_to_share_with: the user's SecureDropbox account
            file_to_share: file path in local pattern
            
        return:
            flag indicates the file sharing succeed or not.
        '''
        
        # get the file sharing info via the dropbox /media restful API.
        # before passing the file_to_share, convert it to dropbox path pattern.
        sharing_info = self.dropbox_handler.client.media(self.path_local_2_dropbox(file_to_share))

        # sharing information. by sending http request to the url, a pure content of the file is returned.
        # A timestamp expire value is decided by dropbox and returned. By default it's six hours until the 
        # url expires. 
        url = sharing_info['url']
        expires = sharing_info['expires']
        
        # generate doc_id based on file path
        doc_id = os.path.basename(file_to_share)

        # get sharing receipient's RSA pub_key.
        response = self.KMS_handler.download_sharing_recipient_RSA_pub_key(self.user.username, self.user.password, self.user.token, user_to_share_with)
        receipient_RSA_pub_key = response.read()
        
        # if no such a user or pub key fetching failed.
        if receipient_RSA_pub_key == CONFIG.FETCH_PUBLIC_KEY_FAILED:
            return False

        if receipient_RSA_pub_key:
            # encrypt the doc_key with receipient's RSA pub key so that receipient could decrypt by the RSA private key
            # held by him own.
            doc_key = self.cryptor.RSA_encryptor(self.user.doc_keychain[doc_id], receipient_RSA_pub_key)
        else:
            doc_key = None

        if doc_key:
            # send the sharing record include the doc metadata, url and expires returned from dropbox.
            return self.KMS_handler.share_file(self.user.username, self.user.password, self.user.token, user_to_share_with, doc_id, doc_key, url, expires)
        else:
            return False
        
    def shared_file(self):
        '''
        get the shared file list from KMS server
        
        parameter:
            None
        
        return:
            shared file list
        '''
        
        # call the shared_file method via KMS_handler and return the result
        return self.KMS_handler.shared_file(self.user.username, self.user.password, self.user.token)

    def login(self):
        '''
            login into the SecureDropbox KMS server. 
            
            parameter:
                None
            
            return:
                flag indicate the login succeed or not
        '''
        
        # call the login method via KMS_handler and the token(timestamp) RSA key pairs and doc key_chain
        # are returned if login succeed. Else token = -1 and other three are None.
        self.user.token, self.user.RSA_pub_key, self.user.RSA_priv_key, self.user.doc_keychain = \
            self.KMS_handler.login(self.user.username, self.user.password)

        # if it's a valid login request, initialize the user information
        if self.user.token and self.user.token != CONFIG.INVALID_USER_INCORRECT_INFO:
            # if valid user then decrypt the encrypted RSA private key with user's password through pbkdf2
            
            # decrypt the RSA private key via own password
            self.user.RSA_priv_key = \
             self.cryptor.AES_decryptor(self.user.RSA_priv_key, self.cryptor.pad_AES_key(self.user.password))
             
            print 'User KMS configuration done'
            
            # decrypt the doc_keys with RSA private key
            if len(self.user.doc_keychain) != 0:
                for key in self.user.doc_keychain.keys():
                    self.user.doc_keychain[key] = \
                        self.cryptor.RSA_decryptor(self.user.doc_keychain[key], self.user.RSA_priv_key)
    
            return True
        
        else:
            
            return False

    def register(self, username, password):
        
        '''
            register a new account in the KMS server
            
            parameter:
                username: username want to register
                password: password want to use
                
            return:
                registration result from KMS server.
        '''
        
        # create temp .pem file ready for storing the RSA key pair.
        private_key_path = '%s_priv.pem' % (username)
        f = open(private_key_path, 'w')
        f.close()
        public_key_path = '%s_pub.pem' % (username)
        f = open(public_key_path, 'w')
        f.close()
        
        print 'register :: generating RSA keys...'
        
        # generating RSA key pair.
        # get a random string as rand_seed
        M2Crypto.Rand.rand_seed (os.urandom (1024))
        
        # generate the RSA key pair via gen_key interface.
        RSA_key = M2Crypto.RSA.gen_key (1024, 65537)
        
        # save both private key and public key
        RSA_key.save_key (private_key_path, None)
        RSA_key.save_pub_key (public_key_path)
        
        # read the public key to memory
        f = open(public_key_path)
        RSA_public_key = f.read()
        f.close()
        os.remove(public_key_path)
        
        # read the private key to memory
        f = open(private_key_path)
        RSA_private_key = f.read()
        f.close()
        os.remove(private_key_path)
        
        # encrypt the RSA private key with password before uploading to the server.
        RSA_private_key = self.cryptor.AES_encryptor(RSA_private_key, self.cryptor.pad_AES_key(password))
        
        # upload RSA key pair and user metadata to registration api and get the return value
        return self.KMS_handler.register(username, password, RSA_public_key, RSA_private_key)

    def show_file_list(self):

        '''
        get file_list record from KMS server for certain user.
        
        parameter:
            None
            
        return:
            a list type file_list include filename, last modification and synchronization situation.
        '''
        file_list = []
        serial_number = 1
        
        # get the local file_list
        local_file_list = os.listdir(self.secure_dropbox_folder_path)
        
        # get file list on KMS server via download_doc_keychain interface of KMS_handler
        KMS_file_list = \
            self.KMS_handler.download_doc_keychain(self.user.username, self.user.password, self.user.token)\
                .keys()

        # matching the local and online file list and getting the synchronization situation
        for filename in local_file_list:
            
            # if it's a file loaded by SecureDropbox properly. The judgement is based on suffix.
            if self.user.username in filename and str(filename).endswith('.enc'):
                
                # indicate the last modification time of certain file. Further function could be done like 
                # version control according to last modification time 
                modification_time = \
                    time.ctime(os.stat(self.secure_dropbox_folder_path + os.path.sep + filename).st_mtime)
    
                # tag a synchronization flag to the file. If the file exists both onlinely and locally
                if filename in KMS_file_list:
                    sync_state = 'sync'
                else:
                    sync_state = 'out-sync'
    
                # generate a file node and append it to the list to be returned.
                file_list_node = [str(serial_number), filename, modification_time, sync_state]
                file_list.append(file_list_node)

                serial_number += 1
        return file_list

    def delete_file(self, file_to_delete):
        '''
        delete a file loaded via SecureDropbox. This method include deleting the local file and KMS server record
        
        parameter:
            file_to_delete: local file name to be deleted.
            
        return:
            flag indicated file deleting succeed or not.
        '''
        
        file_path = file_to_delete
        
        print 'Deleting' + file_path
        # generate doc id based on file local path.
        doc_id = os.path.basename(file_to_delete)
        
        print "Deleting doc_id: %s" % doc_id
        # send the delete file request to KMS server.
        res = self.KMS_handler.delete_doc_keychain(self.user.username, self.user.password, self.user.token, doc_id).read()

        
        if res == CONFIG.DELETE_KEY_SUCCEED:
            try:
                # delete local file after positive response from KMS server
                os.remove(file_path)
            except OSError as e:  # name the Exception `e`
                print "Failed with:", e.strerror  # look what it says
                print "Error code:", e.code 
            return True
        else:
            return False

    def generate_doc_id(self, file_path):
        '''
        generate the doc id.
        
        parameters: 
            file_path: local file system path of the file
        
        return:
            doc_id include username and end up with .enc
        '''
        # test.txt_hahalaugh@gmail.com.enc
        doc_id = os.path.basename(file_path) + '_' + self.user.username + '.enc'
        return doc_id

    def read_file(self, file_to_read):
        '''
            read the AES256 encrypted local file.
            
            parameter:
                file_to_read: local file system path of the file to be read.
                
            return:
                file content in plain text
        '''
        
        # get the doc_id and corresponding AES doc_key
        doc_id = os.path.basename(file_to_read)
        doc_key = self.user.doc_keychain[doc_id]

        temp_file_path = self.secure_dropbox_folder_path + os.path.sep + str(time.time())
        
        # decrypt the target file and put it into temp_file_path
        self.cryptor.decrypt_file(doc_key, file_to_read, temp_file_path)

        # get file content and delete the temp file 
        with open(temp_file_path) as f:
            result = f.read()
        os.remove(temp_file_path)
        
        return result

    def load_file_into_secure_dropbox(self, file_to_load):

        '''
        load a plaintext file into secure dropbox
        the load procedure includes encrypting the target file and copying the file
        to the securedropbox folder in Dropbox app folder.
        
        parameter:
            file_to_load: target file to load in local file system
            
        return:
            upload result returned from KMS server
        '''
        
        # get doc id and corresponding doc key.
        doc_id = self.generate_doc_id(file_to_load)
        doc_key = self.cryptor.generate_new_doc_key()

        # encrypt the file with doc key
        target_file = self.secure_dropbox_folder_path + os.path.sep + doc_id
        self.cryptor.encrypt_file(doc_key, file_to_load, target_file)

        # encrypt the doc key with RSA public key before uploading to KMS
        # print self.user.RSA_pub_key
        doc_key = self.cryptor.RSA_encryptor(doc_key, self.user.RSA_pub_key)

        # upload the encrypted doc_key to KMS
        upload_result = self.KMS_handler.upload_doc_key(self.user.username, self.user.password, self.user.token, doc_id, doc_key)
        # print upload_result
        
        # update local doc key chain. Since everytime reading a file is not through the KMS server but only
        # get doc key from local. So it's essential to update the doc key chain once it is changed.
        self.user.doc_keychain = self.KMS_handler.update_doc_keychain(self.user.username, self.user.password, self.user.token)

        # decrypt the doc keychain. the doc key chain get from KMS server is encrypted with AES256 and user's password as 
        # key seed.
        for key in self.user.doc_keychain.keys():
            self.user.doc_keychain[key] = \
                self.cryptor.RSA_decryptor(self.user.doc_keychain[key], self.user.RSA_priv_key)

        # dump the new doc key chain information and encrypt it.
        with open(self.ini_file, 'w') as ini_file:
            pickle.dump(self.user, ini_file, True)
        self.encrypt_ini()
        
        return upload_result

    def path_local_2_dropbox(self, local_path):
        '''
        Convert local path format to dropbox style(linux)
        
        parameters:
            local_path: path of file in local style
            
        return dropbox path style
        '''
        # add the prefix of Secure dropbox folder to dropbox_path
        dropbox_path = '/Secure Dropbox/' + os.path.basename(local_path)
        return dropbox_path

    def read_shared_file(self, doc_key, url):
        '''
        read shared file in the dropbox. There is no actually file instance to be read. 
        The content of shared file is fetched thourgh url which generated by /media interface of dropbox.
        the shared file has a expiration limitation so once the sharing time is up, KMS server will delete the
        sharing record so that sharing receipient would not get this sharing information locally.
        
        parameter:
            doc_key: encrypted doc key with receipient's RSA pub key. 
            url: sharing url generated by /media interface of Dropbox core API.
            
        return:
            decrypted file content
        '''
        
        # decrypt the doc key with receipient's own private key.
        raw_doc_key = self.cryptor.RSA_decryptor(doc_key, self.user.RSA_priv_key)
        
        # fetch file content by sending get request to the target url.
        encrypted_doc_content = urllib2.urlopen(url).read()
        
        # This is a bug-fixing step. Because of different coding style that dropbox is using, 
        # the file you upload would be distorted with regard to the way how to represent the return character.
        # In win7 it's coded as '0a' but dropbox change it to '0d0a'(more the just a return)
        # It causes an incorrect deciphering procedure since the cipher are changed. 
        encrypted_doc_content.replace(binascii.a2b_hex('0d0a') , binascii.a2b_hex('0a'))
        
        # write the content into a temporary file.
        temp_enc_file_path = str(time.time())
        f = open(temp_enc_file_path, 'wb')
        f.write(encrypted_doc_content)
        f.close()
        
        temp_file_path = self.secure_dropbox_folder_path + os.path.sep + str(time.time()) + '.enc'

        # print raw_doc_key
        # decrypt the file with doc key that just decrypted with receipients' own password.
        self.cryptor.decrypt_file(raw_doc_key, temp_enc_file_path, temp_file_path)

        # get plain text file content
        with open(temp_file_path) as f:
            result = f.read()
            
        # uncomment this to leave log file existed for decryption procedure.
        # os.remove(temp_file_path)
        # os.remove(temp_enc_file_path)
        return result

         
        # return self.cryptor.AES_decryptor(encrypted_doc_content, self.cryptor.pad_AES_key(raw_doc_key))

    
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
