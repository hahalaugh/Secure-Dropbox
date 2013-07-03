from dropbox_handler import DropboxHandler
from file_handler import FileHandler
from kms_handler import KMSHandler
from crypto_handler import CryptoHandler

class SecureDropboxUser():
        
    def __init__(self):
        self.dropbox_handler = DropboxHandler().dropbox_handler
        self.file_handler = FileHandler()
        self.kms_handler = KMSHandler()
        self.crypto_handler = CryptoHandler()
        
user = SecureDropboxUser()
print user.dropbox_handler.account_info()
