import traceback
import re
import os
import sys
import CONFIG
from Cryptor import Cryptor
from KMS import KMS_Handler
from getpass import getpass
from Tkinter import Tk
from tkFileDialog import askopenfilename
from SecureDropbox import SecureDropbox
from SecureDropboxExceptions import DropboxNotInstalledException

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

    def file_list_processor(self):
        file_list = self.secure_dropbox.show_file_list()

        if file_list:
            for file_info in file_list:
                print "%s      %s      %s" % (file_info[0], file_info[1], file_info[2])
        else:
            print 'No local file'

    def file_sharing_processor(self):
        user_to_share_with = None
        while True:
            user_to_share_with = raw_input("User's email address to share with:")
            if user_to_share_with and not re.match(r"[^@]+@[^@]+\.[^@]+", user_to_share_with):
                print 'please input a valid email address'
            else:
                break

        file_to_share = self.load_file_path(enc_file=True)

        if user_to_share_with and file_to_share:
            if self.secure_dropbox.share_file(user_to_share_with, file_to_share):
                print 'file sharing successfully!'
            else:
                print 'file sharing failed'
        else:
            print 'file load failed'

    def file_delete_processor(self):
        
        f = self.load_file_path(enc_file=True)
        if f:
            if self.secure_dropbox.delete_file(f):
                print 'Selected file has been removed from Secure Dropbox'
            else:
                print 'Selected file is not deleted successfully'
        else:
            print 'file load failed'

    def file_load_processor(self):
        
        f = self.load_file_path()
        if f:
            if self.secure_dropbox.load_file_into_secure_dropbox(f) == CONFIG.UPLOAD_KEY_CHAIN_SUCCEED:
                print 'upload doc keychain upload succeed'
            else:
                print 'upload doc keychain failed'
        else:
            print 'load file failed'

    def file_read_processor(self):
        f = self.load_file_path(enc_file=True)
        if f:
            content = self.secure_dropbox.read_file(f)
            print content
        else:
            print 'load file failed'

    def file_shared_processor(self):

        shared_file_list = self.secure_dropbox.shared_file()

        print shared_file_list
        for key in shared_file_list:
            flag = int(key) + 1
            print flag , shared_file_list[key]['doc_id'], shared_file_list[key]['from_user']
  

    def file_read_shared_processor(self):

        flag = -1
        shared_file_list = self.secure_dropbox.shared_file()
        self.file_shared_processor()
        
        print len(shared_file_list)
        print range(len(shared_file_list))
        while flag not in shared_file_list.keys():
            flag = raw_input('Please input the sequence number of shared file to read')
            flag = int(flag)
            flag -= 1
            flag = str(flag)

        print self.secure_dropbox.read_shared_file(shared_file_list[flag]['doc_key'], shared_file_list[flag]['url'])

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

    def get_dropbox_installation_folder(self):
        dropbox_folder = None

        for dirname, dirnames, filenames in os.walk(os.path.expanduser('~')):
            for subdirname in dirnames:
                if subdirname == 'Dropbox':
                    dropbox_folder = os.path.join(dirname, subdirname)
                    break
            if dropbox_folder:
                break
        try:
            if not dropbox_folder:
                raise DropboxNotInstalledException()
        except DropboxNotInstalledException, e:
            print e.exception_info
            sys.exit(0)
        else:
            return dropbox_folder

    def start(self):
        dropbox_installation_folder = self.get_dropbox_installation_folder()
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
                        self.commands[command]()
                    else:
                        continue
                except KeyError:
                    print 'Invalid command. Input ? for help'
                except:
                    print traceback.format_exc()
        else:
            print 'Initialization Failed'

    def load_file_path(self, enc_file=False):
        """

        :param enc_file:
        :return:
        """

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
