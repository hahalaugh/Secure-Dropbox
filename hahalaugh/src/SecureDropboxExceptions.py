class DropboxNotInstalledException(Exception):
    def __init__(self):
        Exception.__init__()
        self.exception_info = 'Dropbox client not installed or could not be found'

