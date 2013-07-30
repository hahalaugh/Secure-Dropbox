from bottle import post, request, run
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3 as lite
import time
import re
import json
import CONFIG
import smtplib
from Crypto.Cipher import AES
from Crypto import Random
import thread

# lambda method to pad and unpad AES key
pad = lambda s: s + (CONFIG.BS - len(s) % CONFIG.BS) * chr(CONFIG.BS - len(s) % CONFIG.BS) 
unpad = lambda s : s[0:-ord(s[-1])]

#database handler connect to sqlite3
db_handler = lite.connect("./SecureDropboxDB.db")
db = db_handler.cursor()


def pad_AES_key(self, key):
    '''
        padding AES key to 32 bit long before encryption
        padding with char 0 or cut the first 32 chars out
    '''
    if len(key) <= 32:
        for i in xrange(32 - len(key)):
            key += '0'
    else:
        key = key[:32]
        
    return key
    
def AES_encryptor(key, plaintext):
    
    """
    Returns hex encoded encrypted value!
    """
    
    if len(key) <= 32:
        for i in xrange(32 - len(key)):
            key += '0'
    else:
        key = key[:32]

    # padding plaintext to the multiple value of 16
    plaintext = pad(plaintext)

    #generate a random iv
    iv = Random.new().read(AES.block_size);
    cryptor = AES.new(key, AES.MODE_CBC, iv)

    #cipher doc include iv and cipher text
    return (iv + cryptor.encrypt(plaintext)).encode("hex")

def AES_decryptor(key, cipher):
    
    """
    Requires hex encoded param to decrypt
    """
    if len(key) <= 32:
        for i in xrange(32 - len(key)):
            key += '0'
    else:
        key = key[:32]
        
    cipher = cipher.decode("hex")

    #extract iv from cipher text
    iv = cipher[:16]
    cipher = cipher[16:]
    cryptor = AES.new(key, AES.MODE_CBC, iv)

    #unpad cipher before return raw plaintext 
    return unpad(cryptor.decrypt(cipher))

def notify_share(from_user, to_user, doc_id, expires):

    '''
        sending a email to the user who is shared a file by others
    '''

    #generate emails content text
    SUBJECT = 'You get a shared file from %s' % (from_user)
    TEXT = 'Please check your shared file infomation in secure dropbox client\nShared by: %s\ndoc_id: %s\nexpires: %s ' % \
            (from_user, doc_id, expires)

    # message format
    message = """\From: %s\nTo: %s\nSubject: %s\n\n%s
    """ % (from_user, "".join(to_user), SUBJECT, TEXT)

    #generate SMTP handler
    s = smtplib.SMTP('smtp.gmail.com:587')
    try:
        s.ehlo()
        s.starttls()   
        print s.login('notification.secure.dropbox@gmail.com', 'dissertation')
        print s.sendmail(from_user, to_user, message)
        s.close()
    except:
        print 'email address not valid'
        
def fetch_pem(username):
    '''
        get pem file content from server's local file system according to the username
    '''
    if username:
        try:
            f_pub = open('./RSA_Key_Inventory/' + username + '_pub.pem')
            f_priv = open('./RSA_Key_Inventory/' + username + '_priv.pem')
            pub_key = f_pub.read()
            priv_key = f_priv.read()
            f_pub.close()
            f_priv.close()
            
            res = {}
            res['pub_key'] = pub_key
            res['priv_key'] = priv_key
            
            return res
        except:
            print 'key fetch error'
    else:
        return None
def is_valid_user(request):

    '''
        user authentication before processing each request
        include username matching, password matching and token matching.
        password is matched by it's hash code and token is used for detect
        if the login operation is too long ago and if a relogin operation is required.
    '''
    print 'is_valid_user :: user authentication...'
    content = request.body.read()
    request.body.seek(0)

    # get user authentication information
    info_dict = json.loads(content)

    # print 'is_valid_user :: user information:' + str(info_dict)
    username = info_dict['username']
    # password = info_dict['password']
    token = info_dict['token']
    current_time = time.time()
    
    sql = "select password from user where username = '%s'" % (username)
    db.execute(sql)
    password = db.fetchone()

    # match password hash code with server's password record.
    # server doesnt store the plaintext password but the salt, iteration number and hash value of the password.
    check_pass = check_password_hash(password[0], info_dict['password'])
    if check_pass:
        print 'is_valid_user :: right username and password. Matching the token...'
        sql = "select token from user where username = '%s'" % (username)
        db.execute(sql)
        res = db.fetchone()
        
        token = res[0]

        # match token. if token is too old then a relogin is required to fresh the token
        if token:
            if current_time - float(token) <= CONFIG.TTE:
                print 'is_valid_user :: user authentication affirmative'
                return CONFIG.VALID_USER
            else:
                print 'is_valid_user :: token expired'
                return CONFIG.INVALID_USER_TIMEOUT
        else:
            print 'is_valid_user :: invalid token'
            return CONFIG.INVALID_USER_NO_TOKEN
    else:
        print 'is_valid_user :: user authentication negative'
        return CONFIG.INVALID_USER_INCORRECT_INFO
'''        
@post('/getsalt')
def getsalt():
    
    content = request.body.read()
    user_info = json.loads(content)
    
    sql = "select salt from user where username = '%s'" % (user_info['username'])
    db.execute(sql)
    res = db.fetchone()
    
    if res:
        response = {}
        response['salt'] = res[0]
        return response
    else:
        return CONFIG.GET_SALT_FAILED
'''
@post('/login')

def login():
    '''
        process login request. include username and password hash value matching.
        a token of current time stamp will be return if login succeed while error
        code for failed login trials.

        RSA key pair would be return as well if login succeed.
    '''
    response = {}
    content = request.body.read()
    user_info = json.loads(content)
    print 'login :: user: %s is trying to log in' % (user_info['username'])
    sql = "select password from user where username = '%s'" % (user_info['username'])
    db.execute(sql)
    temp_password = db.fetchone()
    if temp_password:
        password = temp_password[0]
    else:
        response['token'] = CONFIG.FAILED_LOGIN_TOKEN
        response['pub_key'] = 0
        response['priv_key'] = 0
        print 'login :: user: %s is not in the database' % (user_info['username'])
        return response

    # if password hash matched.
    if check_password_hash(password, user_info['password']):
        print 'login :: user login infomation affirmative'
        print 'login :: generating token'

        #generate timestamp as token
        token = time.time()
        sql = "update user set token = '%s' where username = '%s'" % (token, user_info['username'])
        db.execute(sql)
        db_handler.commit()
        print 'login :: token generated and stored in database: token = %f' % (token)
        print 'login :: get user RSA keys'
        # keys = fetch_pem(user_info['username'])
        sql = "select token, public_key, private_key from user where username = '%s'" % (user_info['username'])
        db.execute(sql)

        #get RSA key pair
        response['token'], response['pub_key'], response['priv_key'] = db.fetchone() 

        print 'login :: keys prepared...'
        
        return response
    else:
        print 'login :: user login infomation negative. token = -1 returnd'

        response['token'] = CONFIG.FAILED_LOGIN_TOKEN
        response['pub_key'] = 0
        response['priv_key'] = 0
        return response

@post('/register')
def register():
    '''
        process registration request from user.
        All the information include username, password, RSA key pair are generated by user end and
        KMS server end only do storage.
    '''
    print 'register :: receive registration request'
    content = request.body.read()

    # print content
    regi_info = json.loads(content)

    print 'register :: registration information: ' + str(regi_info)

    #if it's a valid username.
    if not re.match(r"[^@]+@[^@]+\.[^@]+", regi_info['username']):
        print 'register :: username is not a valid email address'
        return CONFIG.REGISTER_FAILED
    else:
        print 'register :: username is a valid email address'

    
    sql = "select * from user where username = '%s'" % (regi_info['username'])
    db.execute(sql)
    res = db.fetchone()

    #test if there is same username account existed
    if not res:
        print 'register :: no same user exists. begin registration'
        # if regi_info['password'] and regi_info['salt']:
        if regi_info['password']:
            # print 'register :: password and salt not empty'
            print 'register :: password not empty'
            
            print 'register :: generate record for %s in database' % regi_info['username']

            # generate password hash
            password = generate_password_hash(regi_info['password'])
            sql = "insert into user(username, password, public_key, private_key) values('%s','%s','%s','%s')"\
                 % (regi_info['username'], password, regi_info['RSA_pub_key'], regi_info['RSA_priv_key'])

            #generate record in the database
            db.execute(sql)
            db_handler.commit()
            
            print 'register :: insert record successfully'
            return CONFIG.REGISTER_SUCCEED
    else:
        print 'register :: registration failed. same username exists'
        return CONFIG.REGISTER_FAILED
        
@post('/upload_doc_key_chain')
def upload_doc_key_chain():
    '''
        process uploading new doc key chain request.
        If there is same record in database, refresh it.
    '''
    if is_valid_user(request):
        content = request.body.read()
        doc_key_chain = json.loads(content)
        print 'upload_doc_key_chain :: doc_key_chain for %s' % (str(doc_key_chain['doc_id']))
        sql = "select * from key_chain where username = '%s' and doc_id = '%s'" % (doc_key_chain['username'], doc_key_chain['doc_id'])
        db.execute(sql)

        #if there is no such a record
        if not db.fetchone():
            print 'upload_doc_key_chain :: new doc key chain. Inserting...'
            sql = "insert into key_chain(username, doc_id, doc_key) values('%s','%s','%s')"\
             % (doc_key_chain['username'], doc_key_chain['doc_id'], doc_key_chain['doc_key'])
            
            db.execute(sql)
            db_handler.commit()
            print 'upload_doc_key_chain :: key chain added'
            return CONFIG.UPLOAD_KEY_CHAIN_SUCCEED
        else:
            #same record existed, refresh it
            print 'upload_doc_key_chain :: doc key chain existed already. Updating...'
            sql = "update key_chain set doc_key = '%s' where doc_id = '%s'" % (doc_key_chain['doc_key'], doc_key_chain['doc_id'])
            
            db.execute(sql)
            db_handler.commit()
            
            return CONFIG.UPLOAD_KEY_CHAIN_EXISTED
    else:
        return CONFIG.UPLOAD_KEY_CHAIN_FAILED

@post('/download_doc_key_chain')
def download_doc_key_chain():
    '''
        process downloading doc key for certain user
        it return user a dictionary with doc id as key and doc key as value
        Error code returned if failed
    '''
    if is_valid_user(request):
        content = request.body.read()
        key_chain_request = json.loads(content)
        print 'download_doc_key_chain :: download key chain for doc: %s' % (key_chain_request['doc_id'])
        sql = "select doc_key from key_chain where username = '%s' and doc_id = '%s'" \
        % (key_chain_request['username'], key_chain_request['doc_id'])
        
        db.execute(sql)
        res = db.fetchone()
        if res:
            doc_key = res[0]
            print 'download_doc_key_chain :: key = %s' % (doc_key)
            return doc_key
        else:
            print 'download_doc_key_chain :: no key for doc: %s' % (key_chain_request['doc_id'])
            return CONFIG.DOWNLOAD_KEY_CHAIN_FAILED
    else:
        return CONFIG.DOWNLOAD_KEY_CHAIN_FAILED

@post('/delete')
def delete():
    '''
        process deleting doc key record request.
        deleting a doc key will trigger the deletion of corresponding record in file sharing pool.
    '''
    if is_valid_user(request):
        content = request.body.read()
        delete_request = json.loads(content)
        
        print 'delete_request :: user %s try to delete file %s' % \
        (delete_request['username'], delete_request['doc_id'])

        #delete in the doc key chain database
        sql = "delete from key_chain where username = '%s' and doc_id = '%s'" % \
        (delete_request['username'], delete_request['doc_id'])
        db.execute(sql)
        db_handler.commit()

        # also delete record in the sharing pool
        sql = "delete from sharing_pool where from_user = '%s' and doc_id = '%s'" % \
        (delete_request['username'], delete_request['doc_id'])
        db.execute(sql)
        
        db_handler.commit()
        
        return CONFIG.DELETE_KEY_SUCCEED
    
    else:
        return CONFIG.DELETE_KEY_FAILED
        
@post('/cancel_share')
    '''
        process cancel file sharing.
        delete the file sharing record in sharing pool.
    '''
def cancel_share():
    if is_valid_user(request):
        content = request.body.read()
        cancel_share_request = json.loads(content)
        
        print 'cancel_share :: user %s try to cancel file %s sharing with %s' % \
        ((cancel_share_request['username'], cancel_share_request['doc_id'], cancel_share_request['to_user']))

        # if there is such a record
        sql = "select from_user, to_user, doc_id from sharing_pool where from_user = '%s' and to_user = '%s' and doc_id = '%s'"\
        % (cancel_share_request['username'], cancel_share_request['to_user'], cancel_share_request['doc_id'])

        db.execute(sql)

        #delete it
        if db.fetchone():
            sql = "delete from sharing_pool where from_user = '%s' and to_user = '%s' and doc_id = '%s'"\
            % (cancel_share_request['username'], cancel_share_request['to_user'], cancel_share_request['doc_id'])
            
            db.execute(sql)
            db_handler.commit()
            print 'cancel file sharing successfully'
            return CONFIG.FILE_SHARING_CANCEL_SUCCEED
        else:
            print 'no such a file sharing record from %s to %s file: %s' % \
            (cancel_share_request['username'], cancel_share_request['to_user'], cancel_share_request['doc_id'])
            
            return CONFIG.FILE_SHARING_CANCEL_FAILED
    else:
        return CONFIG.FILE_SHARING_CANCEL_FAILED

@post('/share')
def share():
    '''
        process file sharing process.
        essentially add a record in sharing_pool database. An email notification would be made by this processor
        to recipient user.
    '''
    if is_valid_user(request):
        content = request.body.read()
        share_request = json.loads(content)
        print 'share :: file sharing requests: %s' % (str(share_request))
        sql = "select from_user, to_user, doc_id from sharing_pool where from_user = '%s' and to_user = '%s' and doc_id = '%s'"\
        % (share_request['username'], share_request['share_to_user'], share_request['doc_id'])
        
        db.execute(sql)

        # if same record exists, then do nothing.
        if db.fetchone():
            print 'share :: file %s shared with %s already' % (share_request['doc_id'], share_request['share_to_user'])
            return CONFIG.FILE_SHARING_EXISTED
        else:

            #generate file sharing record and notify the recipient user.
            sql = "insert into sharing_pool(from_user, to_user, doc_id, doc_key, url, expires) values('%s','%s','%s','%s','%s','%s')"\
            % (share_request['username'], share_request['share_to_user'], share_request['doc_id'], share_request['doc_key'], share_request['url'], share_request['expires'])
            
            db.execute(sql)
            db_handler.commit()
            print 'share :: file %s shared with %s successfully' % (share_request['doc_id'], share_request['share_to_user'])

            #notify recipient user.
            notify_share(share_request['username'], share_request['share_to_user'], share_request['doc_id'], share_request['expires'])
            
            return CONFIG.FILE_SHARING_SUCCEED
    else:
        return CONFIG.FILE_SHARING_FAILED

@post('/fetch_pub_key')
def fetch_pub_key():
    '''
        processing fetch recipient's RSA public key request.
        It usually happen before source user want to share a file with recipient user
        so he has to fetch R's pub key to encrypt the doc key before generating
        that sharing record in sharing pool.
    '''
    if is_valid_user(request):
        content = request.body.read()
        fetch_pub_key_request = json.loads(content)
        
        print 'fetch_pub_key :: %s fetch the RSA key of %s' % \
        (fetch_pub_key_request['username'], fetch_pub_key_request['share_to_user'])
        
        sql = "select public_key from user where username = '%s'" % (fetch_pub_key_request['share_to_user'])
        db.execute(sql)
        
        res = db.fetchone()
        if res:
            pub_key = res[0]
            print 'fetch_pub_key :: user %s RSA public key fetched' % (fetch_pub_key_request['share_to_user'])
            return pub_key
        else:
            # no user record so return error code
            print 'fetch_pub_key :: no such a user: %s' % (fetch_pub_key_request['share_to_user'])
            return CONFIG.FETCH_PUBLIC_KEY_FAILED
    else:
        return CONFIG. FETCH_PUBLIC_KEY_FAILED

@post('/fetch_own_doc_keychain')
def fetch_own_doc_keychain():
    '''
        process fetching user's own doc key chain request.
        download the doc keychain again to local in a dictionary with doc id as key and doc key as value.
    '''
    if is_valid_user(request):
        content = request.body.read()
        fetch_own_doc_keychain_request = json.loads(content)
        
        print 'fetch_own_doc_keychain :: %s try to get own doc keychain'\
        % (fetch_own_doc_keychain_request['username'])
         
        sql = "select doc_id, doc_key from key_chain where username = '%s'"\
        % (fetch_own_doc_keychain_request['username'])
        
        db.execute(sql)
        result = db.fetchall()
        
        res = {}
        for element in result:
            key = element[0]
            value = element[1]
            res.update({key:value})
        
        print 'fetch_own_doc_keychain :: doc_keychain returned'
        print res
        return res

@post('/fetch_doc_key')
def fetch_doc_key():
    '''
        processing fetch doc key request.
        fetch single doc key by specify the doc id.
    '''
    if is_valid_user(request):
        content = request.body.read()
        fetch_doc_key_request = json.loads(content)
        
        print 'fetch_doc_key :: %s try to get doc_key of %s shared from %s' % \
        (fetch_doc_key_request['username'], fetch_doc_key_request['doc_id'], fetch_doc_key_request['from_username'])


        # get only one doc key from databse and return.
        sql = "select doc_key from sharing_pool where doc_id = '%s' and to_user = '%s' and from_user = '%s'" \
        % (fetch_doc_key_request['doc_id'], fetch_doc_key_request['username'], fetch_doc_key_request['from_username'])
        
        db.execute(sql)
        res = db.fetchone()

@post('/shared_file')
def shared_file():
    '''
        process liting shared file request.
        return the record in sharing pool that recipient is the user.
    '''
    shared_file_list = {}
    if is_valid_user(request):
        content = request.body.read()
        shared_file_request = json.loads(content)
        
        print 'shared_file :: %s try to get file list shared with' % \
        (shared_file_request['username'])
        
        sql = "select doc_id, from_user, expires, url, doc_key from sharing_pool where to_user = '%s'" % (shared_file_request['username'])
        
        db.execute(sql)
        res = db.fetchall()
        for element in xrange(len(res)):
            # generate sharing record and return
            doc_id, from_user, expires, url, doc_key = res[element]
            shared_file_info = {'doc_id': doc_id, 'doc_key' : doc_key, 'from_user' : from_user, 'url' : url, 'expires' : expires}
            shared_file_node = {element: shared_file_info}
            shared_file_list.update(shared_file_node)
        
        print shared_file_list

        if shared_file_list:
            return shared_file_list
        else:
            return None

    else:
        return None

def update_dropbox_sharing_schedule(interval):
    '''
        a time task running in KMS server.
        as long as detect the expiration value has been reached, delete this file sharing record.
    '''
    Dropbox_time_format = '%a, %d %b %Y %H:%M:%S'
    url_to_delete = []
    db_handler = lite.connect("./SecureDropboxDB.db")
    db = db_handler.cursor()
    while True:
        print 'update sharing record'
        sql = "select url,expires from sharing_pool"
        res = db.execute(sql)
        for row in res:

            # convert time format and get the time stamp value.
            expire_time = time.mktime(time.strptime(row[1][:-6], Dropbox_time_format))
            current_time = time.time()
            if current_time >= expire_time:
                url_to_delete.append(row[0])

        #delete sharing record.
        for url in url_to_delete:
            sql = "delete from sharing_pool where url = '%s'" % url
            db.execute(sql)
        
        db_handler.commit()

        # time task, executed every 600 seconds.
        time.sleep(interval)
        
    thread.exit_thread()  
print '123'
thread.start_new_thread(update_dropbox_sharing_schedule, (600,))
# time.sleep(100)

# start the KMS server
run(host='0.0.0.0', port=8080, debug=True)

