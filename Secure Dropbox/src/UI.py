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

    def __init__(self):
        self.secure_dropbox = None
        self.commands = {'ls': self.file_list_processor,
                    'load': self.file_load_processor,
                    'share': self.file_sharing_processor,
                    'delete': self.file_delete_processor,
                    'read': self.file_read_processor,
                    'shared': self.file_shared_processor,
                    'read shared': self.file_read_shared_processor,
                    '?': self.help
                    }
        
        self.local_commands = {'ls': self.local_file_list_processor,
                               # Methods for reading locally and remotely are the same
                               'read': self.file_read_processor,
                                '?': self.local_help
                                }
        
        self.local_mode = False
        
    def local_file_list_processor(self):
        
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
        print "This is the local help"
    
    def file_list_processor(self):
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
        file_list = self.file_list_processor()
        user_to_share_with = None
        file_to_share = None
        
        file_sequence = raw_input("Please indicate the sequence number of file you want to share:")
        
        if not file_list:
            print "no local file to share"
            return
        
        if not file_sequence.isdigit():
            print 'Invalid input'
            return 
        
        file_sequence = int(file_sequence)
        
        if file_sequence > 0 and file_sequence <= len(file_list):
            file_to_share = self.secure_dropbox.secure_dropbox_folder_path + os.path.sep + file_list[file_sequence - 1][1]
        else:
            print "file load failed"
        
        while True:
            user_to_share_with = raw_input("User's email address to share with:")
            if user_to_share_with and not re.match(r"[^@]+@[^@]+\.[^@]+", user_to_share_with):
                print 'please input a valid email address'
            else:
                break

        if user_to_share_with and file_to_share:
            a = self.secure_dropbox.share_file(user_to_share_with, file_to_share) 
            if a:
                print 'file sharing successfully!'
            else:
                print 'file sharing failed'
        else:
            print 'file load failed'

    def file_delete_processor(self):
        
        file_list = self.file_list_processor()
        if not file_list:
            print "No local file to delete"
            return
         
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
            if self.secure_dropbox.delete_file(path):
                print 'Selected file has been removed from Secure Dropbox'
            else:
                print 'Selected file is not deleted successfully'
        else:
            print 'file load failed'

    def file_load_processor(self):
        
        f = self.load_file_path()
        
        if f:
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
        
        file_list = self.file_list_processor()
        file_sequence = raw_input("Please indicate the sequence number of file you want to read:")
        
        if not file_sequence.isdigit():
            print 'Invalid input'
            return 
        
        file_sequence = int(file_sequence)
        
        if not file_list:
            print 'No file to read'
        elif file_sequence > 0 and file_sequence <= len(file_list):
            path = self.secure_dropbox.secure_dropbox_folder_path + os.path.sep + file_list[file_sequence - 1][1]
            content = self.secure_dropbox.read_file(path)
            print content
        else:
            print 'load file failed'

    def file_shared_processor(self):

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

        flag = -1
        shared_file_list = self.file_shared_processor()
        
        while shared_file_list and flag not in shared_file_list.keys():
            flag = raw_input('Please input the sequence number of shared file to read:')
            if flag.isdigit():
                flag = int(flag)
                flag -= 1
                flag = str(flag)
            else:
                print "invalid input"
        
        if flag != -1:
            print self.secure_dropbox.read_shared_file(shared_file_list[flag]['doc_key'], shared_file_list[flag]['url'])
        else:
            print 'Nothing to read'

    def login_UI(self):

        username = None
        while not username:
            username = raw_input('Please input your account:')
            if username and not re.match(r"[^@]+@[^@]+\.[^@]+", username):
                print 'username should be your email address same as you register on dropbox'
                username = None

        password = None
        while not password:
            password = getpass('Please input your password:')

        return username, password

    def register_UI(self):
        username = None
        while not username:
            username = raw_input('Please input your account to register:')
            if username and not re.match(r"[^@]+@[^@]+\.[^@]+", username):
                print 'username should be your email address same as you register on dropbox'
                username = None

        password = None
        while not password:
            password = getpass('Please input your password to register:')

        password_again = None
        while not password_again:
            password_again = getpass('Please confirm your password to register:')

        if username and password and password_again and password == password_again:
            return username, password

    def help(self):
        print 'This is the help document'
        
    def start(self):
        dropbox_installation_folder = self.get_dropbox_installation_folder()
        
        if not dropbox_installation_folder:
            # No local folder. Exit
            print "Dropbox client not installed. Please install the dropbox client before using Secure Dropbox"
            exit(0)
        else:
            if not self.internet_on():
                print "Internet not accessible"
                
                if not self.local_ini_file_existed(dropbox_installation_folder):
                    print "No local configuration file existed. Quit Secure Dropbox"
                    exit(0)
                    
                else:
                    # local mode. Read only
                    self.local_mode = True
                    print "Local configuration file existed. Secure Dropbox in Local Mode"
        
        if self.local_mode:
            username, password = self.login_UI()
            self.secure_dropbox = SecureDropboxLocal(username, password, dropbox_installation_folder)        
        
        else:
            has_account = raw_input("Do you want to register a Secure Dropbox account?Y/N:").upper()
            
            if has_account.__eq__('Y'):
                username, password = self.register_UI()
                
                self.secure_dropbox = SecureDropbox(username, password, dropbox_installation_folder)
                self.secure_dropbox.cryptor = Cryptor()
                self.secure_dropbox.KMS_handler = KMS_Handler(self.secure_dropbox.cryptor)
                if self.secure_dropbox.register(username, password) == CONFIG.REGISTER_SUCCEED:
                    print 'registration succeed'
                else:
                    print 'registration failed'
    
            username, password = self.login_UI()
            self.secure_dropbox = SecureDropbox(username, password, dropbox_installation_folder)
            
        if self.secure_dropbox.initialize():
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
        
        dropbox_folder = None

        for dirname, dirnames, filenames in os.walk(os.path.expanduser('~')):
            for subdirname in dirnames:
                if subdirname == 'Dropbox':
                    dropbox_folder = os.path.join(dirname, subdirname)
                    break
            if dropbox_folder:
                break
            
        return dropbox_folder
    
    def internet_on(self):
        try:
            response = urllib2.urlopen('https://dropbox.com', timeout=5)
            return True
        except urllib2.URLError as err: pass
        return False
    
    def local_ini_file_existed(self, path):
        
        temp_path = path + os.path.sep + 'Secure Dropbox'
        if os.path.isdir(temp_path):
            filenames = os.listdir(temp_path)
            for element in filenames:
                if str(element).endswith('.ini'):
                    return True
            
        return False
    
    def load_file_path(self, enc_file=False):

        Tk().withdraw()
        filename = askopenfilename(title='Select')  # show an "Open" dialog box and return the path to the selected file
        try:
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
