from bottle import get, post, request, run, route, static_file
import sqlite3 as lite
import os
import time
import M2Crypto
import re
import json
import macro

# Time to expire


db_handler = lite.connect("../SD.s3db")
db = db_handler.cursor()

def notify_share(from_user, to_user, doc_id):
    pass
def fetch_pem(username):
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
    
    print 'is_valid_user :: user authentication...'
    content = request.body.read()
    request.body.seek(0)
    
    info_dict = json.loads(content)

    print 'is_valid_user :: user information:' + str(info_dict)
    username = info_dict['username']
    password = info_dict['password']
    token = info_dict['token']
    current_time = time.time()
    
    sql = "select * from user where username = '%s' and password = '%s'" % (username, password)
    db.execute(sql)
    res = db.fetchone()
    
    if res:
        print 'is_valid_user :: right username and password. Matching the token...'
        sql = "select token from user where username = '%s'" % (username)
        db.execute(sql)
        res = db.fetchone()
        
        token = res[0]
        if token:
            if current_time - float(token) <= macro.TTE:
                print 'is_valid_user :: user authentication affirmative'
                return macro.VALID_USER
            else:
                print 'is_valid_user :: token expired'
                return macro.INVALID_USER_TIMEOUT
        else:
            print 'is_valid_user :: invalid token'
            return macro.INVALID_USER_NO_TOKEN
    else:
        print 'is_valid_user :: user authentication negative'
        return macro.INVALID_USER_INCORRECT_INFO
        
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
        return macro.GET_SALT_FAILED

@post('/login')
def login():
    
    content = request.body.read()
    user_info = json.loads(content)
    print 'login :: user: %s is trying to log in' % (user_info['username'])
    sql = "select * from user where username = '%s' and password = '%s'" % (user_info['username'], user_info['password'])
    db.execute(sql)
    res = db.fetchone()
    
    if res:
        print 'login :: user login infomation affirmative'
        print 'login :: generating token'
        token = time.time()
        sql = "update user set token = '%s' where username = '%s'" % (token, user_info['username'])
        db.execute(sql)
        db_handler.commit()
        print 'login :: token generated and stored in database: token = %f' % (token)
        print 'login :: get user RSA keys'
        keys = fetch_pem(user_info['username'])
        
        response = {}
        response['token'] = token
        response.update(keys)
        
        print 'login :: keys prepared...'
        
        return response
    else:
        print 'login :: user login infomation negative. token = -1 returnd'
        response = {}
        response['token'] = -1
        return response

@post('/register')
def register():
    print 'register :: receive registration request'
    content = request.body.read()

    # print content
    regi_info = json.loads(content)

    print 'register :: registration information: ' + str(regi_info)
    if not re.match(r"[^@]+@[^@]+\.[^@]+", regi_info['username']):
        print 'register :: username is not a valid email address'
        return macro.REGISTER_FAILED
    else:
        print 'register :: username is a valid email address'
    
    sql = "select * from user where username = '%s'" % (regi_info['username'])
    db.execute(sql)
    res = db.fetchone()

    if not res:
        print 'register :: no same user exists. begin registration'
        if regi_info['password'] and regi_info['salt']:
            print 'register :: password and salt not empty'
            private_key_path = './RSA_Key_Inventory/%s_priv.pem' % (regi_info['username'])
            public_key_path = './RSA_Key_Inventory/%s_pub.pem' % (regi_info['username'])
            
            print 'register :: generating RSA keys...'
            M2Crypto.Rand.rand_seed (os.urandom (1024))
            RSA_key = M2Crypto.RSA.gen_key (1024, 65537)
            RSA_key.save_key (private_key_path, None)
            RSA_key.save_pub_key (public_key_path)
            
            f = open(public_key_path)
            public_key = f.read()
            f.close()
            
            f = open(private_key_path)
            private_key = f.read()
            f.close()
            
            print 'register :: generate record for %s in database' % regi_info['username']
            sql = "insert into user(username, password, salt, public_key, private_key) values('%s','%s','%s','%s','%s')"\
                 % (regi_info['username'], regi_info['password'], regi_info['salt'], public_key, private_key)
            
            db.execute(sql)
            db_handler.commit()
            
            print 'register :: insert record successfully'
            return macro.REGISTER_SUCCEED
        else:
            print 'register :: registration failed. same username exists'
            return macro.REGISTER_FAILED
        
@post('/upload_doc_key_chain')
def upload_doc_key_chain():
    if is_valid_user(request):
        content = request.body.read()
        doc_key_chain = json.loads(content)
        print 'upload_doc_key_chain :: doc_key_chain for %s' % (str(doc_key_chain['doc_id']))
        sql = "select * from key_chain where username = '%s' and doc_id <> '%s'" % (doc_key_chain['username'], doc_key_chain['doc_id'])
        db.execute(sql)
        
        if not db.fetchone():
            print 'upload_doc_key_chain :: new doc key chain. Inserting...'
            sql = "insert into key_chain(username, doc_id, doc_key) values('%s','%s','%s')"\
             % (doc_key_chain['username'], doc_key_chain['doc_id'], doc_key_chain['doc_key'])
            
            db.execute(sql)
            db_handler.commit()
            print 'upload_doc_key_chain :: key chain added'
            return macro.UPLOAD_KEY_CHAIN_SUCCEED
        else:
            print 'upload_doc_key_chain :: doc key chain existed already'
            return macro.UPLOAD_KEY_CHAIN_FAILED
    else:
        return macro.UPLOAD_KEY_CHAIN_FAILED

@post('/download_doc_key_chain')
def download_doc_key_chain():
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
            return macro.DOWNLOAD_KEY_CHAIN_FAILED
    else:
        return macro.DOWNLOAD_KEY_CHAIN_FAILED

@post('/cancel_share')
def cancel_share():
    if is_valid_user(request):
        content = request.body.read()
        cancel_share_request = json.loads(content)
        
        print 'cancel_share :: user %s try to cancel file %s sharing with %s' % \
        ((cancel_share_request['username'], cancel_share_request['doc_id'], cancel_share_request['to_user']))
        
        sql = "select from_user, to_user, doc_id from sharing_pool where from_user = '%s' and to_user = '%s' and doc_id = '%s'"\
        % (cancel_share_request['username'], cancel_share_request['to_user'], cancel_share_request['doc_id'])

        db.execute(sql)
        if db.fetchone():
            sql = "delete from sharing_pool where from_user = '%s' and to_user = '%s' and doc_id = '%s'"\
            % (cancel_share_request['username'], cancel_share_request['to_user'], cancel_share_request['doc_id'])
            
            db.execute(sql)
            db_handler.commit()
            print 'cancel file sharing successfully'
            return macro.FILE_SHARING_CANCEL_SUCCEED
        else:
            print 'no such a file sharing record from %s to %s file: %s' % \
            (cancel_share_request['username'], cancel_share_request['to_user'], cancel_share_request['doc_id'])
            
            return macro.FILE_SHARING_CANCEL_FAILED
    else:
        return macro.FILE_SHARING_CANCEL_FAILED

@post('/share')
def share():
    if is_valid_user(request):
        content = request.body.read()
        share_request = json.loads(content)
        print 'share :: file sharing requests: %s' % (str(share_request))
        sql = "select from_user, to_user, doc_id from sharing_pool where from_user = '%s' and to_user = '%s' and doc_id = '%s'"\
        % (share_request['username'], share_request['to_user'], share_request['doc_id'])
        
        db.execute(sql)
        
        if db.fetchone():
            print 'share :: file %s shared with %s already' % (share_request['doc_id'], share_request['to_user'])
            return macro.FILE_SHARING_FAILED
        else:
            sql = "insert into sharing_pool(from_user, to_user, doc_id, doc_key) values('%s','%s','%s','%s')"\
            % (share_request['username'], share_request['to_user'], share_request['doc_id'], share_request['doc_key'])
            
            db.execute(sql)
            db_handler.commit()
            print 'share :: file %s shared with %s successfully' % (share_request['doc_id'], share_request['to_user'])
            notify_share(share_request['username'], share_request['to_user'], share_request['doc_id'])
            
            return macro.FILE_SHARING_SUCCEED
    else:
        return macro.FILE_SHARING_FAILED

@post('/fetch_pub_key')
def fetch_pub_key():
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
            print 'fetch_pub_key :: no such a user: %s' % (fetch_pub_key_request['share_to_user'])
            return macro.FETCH_PUBLIC_KEY_FAILED
    else:
        return macro. FETCH_PUBLIC_KEY_FAILED

@post('/fetch_doc_key')
def fetch_doc_key():
    if is_valid_user(request):
        content = request.body.read()
        fetch_doc_key_request = json.loads(content)
        
        print 'fetch_doc_key :: %s try to get doc_key of %s shared from %s' % \
        (fetch_doc_key_request['username'], fetch_doc_key_request['doc_id'], fetch_doc_key_request['from_username'])
        
        sql = "select doc_key from sharing_pool where doc_id = '%s' and to_user = '%s' and from_user = '%s'" \
        % (fetch_doc_key_request['doc_id'], fetch_doc_key_request['username'], fetch_doc_key_request['from_username'])
        
        db.execute(sql)
        res = db.fetchone()
        
        if res:
            doc_key = res[0]
            print 'fetch_doc_key :: doc key of %s fetched successfully' % (fetch_doc_key_request['doc_id'])
            return doc_key
        else:
            print 'fetch_doc_key :: no such a key for doc: %s' % (fetch_doc_key_request['doc_id'])
            return macro.DOC_KEY_FETCH_FAILED
    else:
        return macro.DOC_KEY_FETCH_FAILED

run(host='localhost', port=8080, debug=True)
