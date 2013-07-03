import urllib, urllib2
import json
import time


def login_test():
    url = 'http://127.0.0.1:8080/login'
    username = 'hahalaugh@gmail.com' 
    values = {'username' : username,
              'password' : '123456',
              'salt' : 'hahalaugh' }
    
    data_raw = json.dumps(values)
    print data_raw
    
    req = urllib2.Request(url, data_raw)
    
    response = urllib2.urlopen(req)
    
    res = json.loads(response.read())
    
    print res['token']
    return res['token']
def register_test():
    url = 'http://127.0.0.1:8080/register'
    username = 'hahalaugh@gmail.com'
    values = {'username' : username,
              'password' : '123456',
              'salt' : 'hahalaugh' }
    
    data_raw = json.dumps(values)
    print data_raw
    
    req = urllib2.Request(url, data_raw)
    
    response = urllib2.urlopen(req)
    
    print response.read()
def get_salt_test():
    url = 'http://127.0.0.1:8080/getsalt'
    username = 'juntao.gu@gmail.com'
    values = {'username' : username}
    
    data_raw = json.dumps(values)
    print data_raw
    
    req = urllib2.Request(url, data_raw)
    
    response = urllib2.urlopen(req)
    
    res = json.loads(response.read())
    
    print res['salt']
def upload_doc_key_chain_test():
    token = login_test()
    url = 'http://127.0.0.1:8080/upload_doc_key_chain'
    username = 'juntao.gu@gmail.com'
    values = {'username' : username,
          'password' : '123456',
          'token' : token,
          'doc_id' : 'hehe.txt',
          'doc_key' : '12345678',
          }
    data_raw = json.dumps(values)
    print data_raw
    
    req = urllib2.Request(url, data_raw)
    
    response = urllib2.urlopen(req)
    
    print response.read()

def download_doc_key_chain_test():
    
    token = login_test()
    url = 'http://127.0.0.1:8080/download_doc_key_chain'
    username = 'juntao.gu@gmail.com'
    values = {'username' : username,
          'password' : '123456',
          'token' : token,
          'doc_id' : 'hehe.txt',
          }
    data_raw = json.dumps(values)
    print data_raw
    
    req = urllib2.Request(url, data_raw)
    
    response = urllib2.urlopen(req)
    
    print response.read()
def share_test():
    token = login_test()
    url = 'http://127.0.0.1:8080/share'
    username = 'juntao.gu@gmail.com'
    values = {'username' : username,
          'password' : '123456',
          'token' : token,
          'doc_id' : 'hehe.txt',
          'doc_key' : 'abcdefg',
          'to_user' : 'hahalaugh@gmail.com'
          }
    data_raw = json.dumps(values)
    print data_raw
    
    req = urllib2.Request(url, data_raw)
    
    response = urllib2.urlopen(req)
    
    print response.read()
def cancel_share_test():
    token = login_test()
    url = 'http://127.0.0.1:8080/cancel_share'
    username = 'juntao.gu@gmail.com'
    values = {'username' : username,
          'password' : '123456',
          'token' : token,
          'doc_id' : 'hehe.txt',
          'doc_key' : 'abcdefg',
          'to_user' : 'hahalaugh@gmail.com'
          }
    data_raw = json.dumps(values)
    print data_raw
    
    req = urllib2.Request(url, data_raw)
    
    response = urllib2.urlopen(req)
    
    print response.read()
def fetch_pub_key_test():
    token = login_test()
    url = 'http://127.0.0.1:8080/fetch_pub_key'
    username = 'juntao.gu@gmail.com'
    values = {'username' : username,
          'password' : '123456',
          'token' : token,
          'doc_id' : 'hehe.txt',
          'doc_key' : 'abcdefg',
          'share_to_user' : 'hahalaugh@gmail.com'
          }
    data_raw = json.dumps(values)
    print data_raw
    
    req = urllib2.Request(url, data_raw)
    
    response = urllib2.urlopen(req)
    
    print response.read()
def fetch_doc_key_test():
    token = login_test()
    url = 'http://127.0.0.1:8080/fetch_doc_key'
    username = 'hahalaugh@gmail.com'
    values = {'username' : username,
          'password' : '123456',
          'token' : token,
          'doc_id' : 'hehe.txt',
          'from_username' : 'juntao.gu@gmail.com'
          }
    data_raw = json.dumps(values)
    print data_raw
    
    req = urllib2.Request(url, data_raw)
    
    response = urllib2.urlopen(req)
    
    print response.read()
# register_test()
# login_test()
# get_salt_test()
# upload_doc_key_chain_test()
# download_doc_key_chain_test()
share_test()
cancel_share_test()
# fetch_pub_key_test()
fetch_doc_key_test()