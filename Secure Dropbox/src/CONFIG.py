# application management information from Dropbox
APP_KEY = 'c8ht5mh6z6y5g82'
APP_SECRET = 'jaonmrivtj18vdd'
ACCESS_TYPE = 'dropbox'

# The token returned when login failed
FAILED_LOGIN_TOKEN = -1


# Server has been deployed on Amazon EC2
SERVER_URL = 'http://54.213.99.125:8080/'
# SERVER_URL = 'http://54.213.96.57:8080/'
# SERVER_URL = 'http://127.0.0.1:8080/'

# ini_file suffix
INI_FILE = '_secure_dropbox.ini'

# time to expire. When difference between login token and current time 
# is bigger than 3600, a relogin operation is required.
TTE = 3600

# delete request result flag
DELETE_KEY_SUCCEED = 'DELETE KEY SUCCEED'
DELETE_KEY_FAILED = 'DELETE KEY FAILED'

# upload key chain request result flag
UPLOAD_KEY_CHAIN_SUCCEED = 'UPLOAD KEY CHAIN SUCCEED'
UPLOAD_KEY_CHAIN_EXISTED = 'UPLOAD KEY CHAIN EXISTED'
UPLOAD_KEY_CHAIN_FAILED = 'UPLOAD KEY CHAIN FAILED'

# update key chain request result flag
DOWNLOAD_KEY_CHAIN_FAILED = 'DOWNLOAD KEY CHAIN FAILED'

# sharing file request result flag
FILE_SHARING_SUCCEED = 'FILE SHARING SUCCEED'
FILE_SHARING_EXISTED = 'FILE SHARING EXISTED'
FILE_SHARING_FAILED = 'FILE SHARING FAILED'

# cancel sharing file request result flag. Not used for now.
FILE_SHARING_CANCEL_SUCCEED = 'FILE SHARING CANCEL SUCCEED'
FILE_SHARING_CANCEL_FAILED = 'FILE SHARING CANCEL FAILED'

# user login information. Different error number.
INVALID_USER_TIMEOUT = -2
INVALID_USER_INCORRECT_INFO = -1
INVALID_USER_NO_TOKEN = 0
VALID_USER = 1

# get salt request flag
GET_SALT_FAILED = 'GET SALT FAILED'

# delete request result flag
REGISTER_SUCCEED = 'REGISTER SUCCEED'
REGISTER_FAILED = 'REGISTER FAILED'

# delete request result flag
FETCH_PUBLIC_KEY_FAILED = 'FETCH PUBLIC KEY FAILED'

# delete request result flag
DOC_KEY_FETCH_SUCCEED = 'DOC KEY FETCH SUCCEED'
DOC_KEY_FETCH_FAILED = 'DOC KEY FETCH FAILED'

# flag to indicate AES decryption or encryption algorithm
ENC = 1
DEC = 0

# password hash parameters
SHA_ITERATION = 1000
KEY_LEN = 32

# block size of AES
BS = 16
