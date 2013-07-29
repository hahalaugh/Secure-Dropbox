import os
import urllib2
import traceback
import CONFIG
from Cryptor import Cryptor
from KMS import KMS_Handler
from getpass import getpass
from Tkinter import Tk
from tkFileDialog import askopenfilename
from SecureDropbox import SecureDropbox
from SecureDropboxLocal import SecureDropboxLocal
import re

class SecureDropbox_UI(object):

    '''
    Main user interface of SecureDropbox
    '''
    def __init__(self):
        # secure dropbox instance to be generated in start method
        self.secure_dropbox = None
        
        # regular command set. Used when SecureDropbox in regular mode(Internet is accessible).
        self.commands = {'ls': self.file_list_processor,
                    'load': self.file_load_processor,
                    'share': self.file_sharing_processor,
                    'delete': self.file_delete_processor,
                    'read': self.file_read_processor,
                    'shared': self.file_shared_processor,
                    'read shared': self.file_read_shared_processor,
                    '?': self.help
                    }
        
        # local command set. Used when SecureDropbox in local mode(Internet is not accessible) 
        self.local_commands = {'ls': self.local_file_list_processor,
                               # Methods for reading locally and remotely are the same
                               'read': self.file_read_processor,
                                '?': self.local_help
                                }
        
        # local mode is defautly set False but might be changed when detecting Internet connection situation.
        self.local_mode = False
        
    def local_file_list_processor(self):
        
        '''
        print file list and return it to the invoker in local mode
        
        return:
            formated local file list information
        '''
        
        # get generated file list
        file_list = self.secure_dropbox.show_file_list()
        
        width = 130
        sequence_width = 10
        filename_width = 80
        mod_time_width = 40
        header_format = '%-*s%-*s%-*s'
        data_format = '%-*s%-*s%-*s'
        
        print '=' * width
        print header_format % (sequence_width, 'Seq', filename_width, 'File', mod_time_width, 'Last Modification')
        print '-' * width
        
        if file_list:
            for file_info in file_list:
                print data_format % (sequence_width, file_info[0], filename_width, file_info[1], mod_time_width, file_info[2])
            return file_list
        else:
            print 'No local file'
            return file_list
    
    def local_help(self):
        '''
        print local mode help information
        '''
        print '''
            ls:           list the files in SecureDropbox
            read:         read loaded files in SecureDropbox
        '''
    
    def file_list_processor(self):
        
        '''
        print file list and return it to the invoker in regular mode
        
        return:
            formated local file list information
        '''
        # get generated file list
        file_list = self.secure_dropbox.show_file_list()

        width = 150
        sequence_width = 10
        filename_width = 80
        mod_time_width = 40
        sync_flag_width = 20
        header_format = '%-*s%-*s%-*s%-*s'
        data_format = '%-*s%-*s%-*s%-*s'
        
        print '=' * width
        print header_format % (sequence_width, 'Seq', filename_width, 'File', mod_time_width, 'Last Modification', sync_flag_width, 'Sync Flag')
        print '-' * width
        
        if file_list:
            for file_info in file_list:
                print data_format % (sequence_width, file_info[0], filename_width, file_info[1], mod_time_width, file_info[2], sync_flag_width, file_info[3])
        return file_list


    def file_sharing_processor(self):
        '''
        print sharable files information and get user input about who to share and which file to share
        '''
        
        # get sharable files list
        file_list = self.file_list_processor()
        user_to_share_with = None
        file_to_share = None
        
        # get file sequence number to be shared
        file_sequence = raw_input("Please indicate the sequence number of file you want to share:")
        
        if not file_list:
            print "no local file to share"
            return
        
        if not file_sequence.isdigit():
            print 'Invalid input'
            return 
        
        file_sequence = int(file_sequence)
        
        # if file is out of synchronization(only existed locally but no corresponding record on KMS server), it cannot be shared
        # unsynchronized situation might owing to not proper file load operation like directly drag file into
        # Secure Dropbox Folder
        if file_list[file_sequence - 1][3] == 'out-sync':
            print 'out-sync file could not be shared with other users'
        elif file_sequence > 0 and file_sequence <= len(file_list):
            file_to_share = self.secure_dropbox.secure_dropbox_folder_path + os.path.sep + file_list[file_sequence - 1][1]
        else:
            print "file load failed"
        
        while True:
            # get sharing recipient's email address
            user_to_share_with = raw_input("User's email address to share with:")
            
            # must be a valid email address format
            if user_to_share_with and not re.match(r"[^@]+@[^@]+\.[^@]+", user_to_share_with):
                print 'please input a valid email address'
            else:
                break

        if user_to_share_with and file_to_share:
            # share the file and print the result form KMS server
            a = self.secure_dropbox.share_file(user_to_share_with, file_to_share) 
            if a:
                print 'file sharing successfully!'
            else:
                print 'file sharing failed'
        else:
            print 'file load failed'

    def file_delete_processor(self):
        
        '''
        get user's input about which file to be deleted
        '''
        
        # generate and print local file list
        file_list = self.file_list_processor()
        if not file_list:
            print "No local file to delete"
            return
         
        # get file sequence number to be deleted
        file_sequence = raw_input("Please indicate the sequence number of file you want to delete:")
        if not file_sequence.isdigit():
            print 'Invalid input'
            return 
        
        file_sequence = int(file_sequence)
        if file_sequence > 0 and file_sequence <= len(file_list):
            path = self.secure_dropbox.secure_dropbox_folder_path + os.path.sep + file_list[file_sequence - 1][1]
        else:
            print "Invalid input"
        
        if path:
            # if a valid path, then delete the file and print result
            if self.secure_dropbox.delete_file(path):
                print 'Selected file has been removed from Secure Dropbox'
            else:
                print 'Selected file is not deleted successfully'
        else:
            print 'file load failed'

    def file_load_processor(self):
        
        '''
            load a file into SecureDropbox. Currently only .txt file is supported
        '''
        
        # invoke a TKinter file loader. the path is returned as f.
        f = self.load_file_path()
        
        if f:
            # if f is a valid file path then load the corresponding file and print the result
            res = self.secure_dropbox.load_file_into_secure_dropbox(f)
            if res == CONFIG.UPLOAD_KEY_CHAIN_SUCCEED:
                print 'upload doc keychain upload succeed'
            elif res == CONFIG.UPLOAD_KEY_CHAIN_EXISTED:
                print 'upload doc keychain existed and replaced with new doc key.'
            else:
                print 'upload doc keychain failed'
        else:
            print 'load file failed'

    def file_read_processor(self):
        
        '''
        get user's input of which file to read and print the file content
        '''
        
        # generate and print file list
        file_list = self.file_list_processor()
        
        # get user's input wrt sequence number of file to read
        file_sequence = raw_input("Please indicate the sequence number of file you want to read:")
        
        if not file_sequence.isdigit():
            print 'Invalid input'
            return 
        
        file_sequence = int(file_sequence)
        
        if not file_list:
            print 'No file to read'
        elif file_list[file_sequence - 1][3] == 'out-sync':
            print 'Out sync file is not allow to read because it is not loaded via Secure Dropbox Client.'
        elif file_sequence > 0 and file_sequence <= len(file_list):
            path = self.secure_dropbox.secure_dropbox_folder_path + os.path.sep + file_list[file_sequence - 1][1]
            
            # if a valid path, call the read_file function and print the decrypted content as result
            content = self.secure_dropbox.read_file(path)
            
            print content
        else:
            print 'load file failed'

    def file_shared_processor(self):

        '''
        print file shared by other with user himself.
        '''
        
        # get shared file list 
        shared_file_list = self.secure_dropbox.shared_file()
        
        width = 150
        sequence_width = 10
        doc_id_width = 80
        from_user_width = 60

        header_format = '%-*s%-*s%-*s'
        data_format = '%-*s%-*s%-*s'
        print '=' * width
        print header_format % (sequence_width, 'Seq', doc_id_width, 'Doc ID', from_user_width, 'Shared By')
        print '-' * width
        
        if shared_file_list:
            for key in range(len(shared_file_list)):
                seq = key + 1
                print data_format % (sequence_width, str(seq), doc_id_width, shared_file_list[str(key)]['doc_id'], from_user_width, shared_file_list[str(key)]['from_user'])
        
        return shared_file_list
    def file_read_shared_processor(self):

        '''
        print file shared by other with user himself. 
        Then get user's input about sequence number of which shared file to read
        '''
        
        flag = -1
        
        # get shared file list
        shared_file_list = self.file_shared_processor()
        
        # get user input of sn of shared file to read
        while shared_file_list and flag not in shared_file_list.keys():
            flag = raw_input('Please input the sequence number of shared file to read:')
            if flag.isdigit():
                flag = int(flag)
                flag -= 1
                flag = str(flag)
            else:
                print "invalid input"
        
        if flag != -1:
            # if valid input then print shared file content
            print self.secure_dropbox.read_shared_file(shared_file_list[flag]['doc_key'], shared_file_list[flag]['url'])
        else:
            print 'Nothing to read'

    def login_UI(self):

        '''
        get user's login information input and return the username and password to invoker.
        '''
        # get the username
        username = None
        while not username:
            username = raw_input('Please input your account:')
            if username and not re.match(r"[^@]+@[^@]+\.[^@]+", username):
                print 'username should be your email address same as you register on dropbox'
                username = None

        # get the password
        password = None
        while not password:
            password = getpass('Please input your password:')

        return username, password

    def register_UI(self):
        
        '''
        get user's registration information input and return the username and password to invoker.
        '''
        
        # get the username
        username = None
        while not username:
            username = raw_input('Please input your account to register:')
            if username and not re.match(r"[^@]+@[^@]+\.[^@]+", username):
                print 'username should be your email address same as you register on dropbox'
                username = None

        # get the password
        password = None
        while not password:
            password = getpass('Please input your password to register:')

        # double check the password
        password_again = None
        while not password_again:
            password_again = getpass('Please confirm your password to register:')

        # if password are the same
        if username and password and password_again and password == password_again:
            return username, password
        else:
            print 'invalid input. Different user password'
            return None, None

    def help(self):
        '''
            print regular mode help information
        '''
        
        print '''
            ls:               list the files in SecureDropbox
            load:             load a plain text file to SecureDropbox
            share:            share the file in SecureDropbox with other SecureDropbox users
            delete:           delete files in SecureDropbox
            read:             read loaded files in SecureDropbox
            shared:           check files shared with me via SecureDropbox
            read shared:      read files shared with me via SecureDropbox
        '''
        
    def start(self):
        
        '''
            most initialization operation of SecureDropbox UI is done here.
        '''
        
        # get the local dropbox installation folder path
        dropbox_installation_folder = self.get_dropbox_installation_folder()
        
        # if there is no such a folder which indicate that dropbox client is not installed
        if not dropbox_installation_folder:
            
            # No local folder. Exit
            print "Dropbox client not installed. Please install the dropbox client before using Secure Dropbox"
            exit(0)
        else:
            
            # test the internet connection situation
            if not self.internet_on():
                
                # internet not accessible so switch to local mode
                print "Internet not accessible"
                
                # no ini file existed so no way to decrypt any existing file. Quit the programme
                if not self.local_ini_file_existed(dropbox_installation_folder):
                    print "No local configuration file existed. Quit Secure Dropbox"
                    exit(0)
                    
                else:
                    # set to local mode. Read only
                    self.local_mode = True
                    print "Local configuration file existed. Secure Dropbox in Local Mode"
        
        # if programme in local mode, initialize in local way
        if self.local_mode:
            
            # call the same login UI
            username, password = self.login_UI()
            
            # but generate the SecureDropbox in local mode
            self.secure_dropbox = SecureDropboxLocal(username, password, dropbox_installation_folder)        
        
        else:
            # internet accessible. Ask user if want to register a SecureDropbox accuont
            has_account = raw_input("Do you want to register a Secure Dropbox account?Y/N:").upper()
            
            if has_account.__eq__('Y'):
                
                # call the register UI and get username and password
                username, password = self.register_UI()
                
                if username and password:
                    
                    # initialization in regular way. Registration procedure need cryptor to crypt the RSA private key
                    # SecureDropbox instance to generate RSA key pair and KMS handler to send the request to KMS server
                    self.secure_dropbox = SecureDropbox(username, password, dropbox_installation_folder)
                    self.secure_dropbox.cryptor = Cryptor()
                    self.secure_dropbox.KMS_handler = KMS_Handler(self.secure_dropbox.cryptor)
                    
                    # process registration request
                    if self.secure_dropbox.register(username, password) == CONFIG.REGISTER_SUCCEED:
                        print 'registration succeed'
                    else:
                        print 'registration failed'
                else:
                    print 'registration failed. Invalid input'
    
            # switch to login UI
            username, password = self.login_UI()
            
            # and regeneration a SecureDropbox instance again. 
            # newly registered user and current user may not be the same one.
            self.secure_dropbox = SecureDropbox(username, password, dropbox_installation_folder)
            
        # initialize is the method that actually do most initialization work for SecureDropbox instance but not
        # the constructor
        if self.secure_dropbox.initialize():
            # get into a dead loop. It works as a command line interface
            while True:
                try:
                    command = raw_input('Secure Dropbox:').lower()
                    if command:
                        if self.local_mode:
                            self.local_commands[command]()
                        else:
                            self.commands[command]()
                    else:
                        continue
                except KeyError:
                    print 'Invalid command. Input ? for help'
                except:
                    print traceback.format_exc()
        else:
            print 'Initialization Failed'
            
    def get_dropbox_installation_folder(self):
        
        '''
            Search local folder by name and decide which on is the Dropbox client installation folder.
            Please make sure there is no same name folder as Dropbox client in your file system.
            It may cause every file is not load into the effective dropbox folder so that not synchronization
            of file sharing operation could be done
        '''
        dropbox_folder = None

        # recursively search if there is a folder named Dropbox
        for dirname, dirnames, filenames in os.walk(os.path.expanduser('~')):
            for subdirname in dirnames:
                if subdirname == 'Dropbox':
                    dropbox_folder = os.path.join(dirname, subdirname)
                    break
            if dropbox_folder:
                break
        
        # return the result
        return dropbox_folder
    
    def internet_on(self):
        '''
            detect if Internet is accessible by visiting dropbox page.
        '''
        try:
            # send http get request to dropbox homepage
            response = urllib2.urlopen('https://dropbox.com', timeout=20)
            return True
        # exception occurs if there is no response.
        except urllib2.URLError as err: pass
        return False
    
    
    def local_ini_file_existed(self, path):
        '''
            detect if there is any ini_file existed in SecureDropbox Folder
        '''
        temp_path = path + os.path.sep + 'Secure Dropbox'
        if os.path.isdir(temp_path):
            filenames = os.listdir(temp_path)
            for element in filenames:
                if str(element).endswith('.ini'):
                    return True
            
        return False
    
    def load_file_path(self, enc_file=False):

        '''
            call the TKinter file loader to get the selected file's path
        '''
        Tk().withdraw()
        # show an "Open" dialog box and return the path to the selected file
        filename = askopenfilename(title='Select')  
        try:
            # can only load file suffix is .txt
            if not enc_file:
                assert filename.endswith(".txt"), 'currently only support txt files'
            else:
                assert filename.endswith(".enc"), 'please select file ends up with .enc'
                assert filename.find(self.secure_dropbox.user.username), 'please select your file only'
        except AssertionError, e:
            print e
            return None
        else:
            return filename
