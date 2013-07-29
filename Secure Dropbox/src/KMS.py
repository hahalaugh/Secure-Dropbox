import CONFIG
import json
import urllib2
import os
import M2Crypto
import sys

class KMS_Handler(object):
    '''
        KMS_Handler communicate with Restful API of KMS server. 
        Request to be sent would be encapsulated in a dictionary and send via 
        send_request_to_server method in json. response in json as well.
        
        Attributes:
            cryptor: cryptography operation is sometimes required during communication
    '''
    def __init__(self, cryptor):
        self.cryptor = cryptor

    def send_request_to_server(self, url, values):
        try:
            # dump data into json format. here values is a dictionary instance
            data_raw = json.dumps(values)
            
            # generate the request and send the http post request to KMS_server
            req = urllib2.Request(url, data_raw)
            
            # get response from KMS_server. Communication error could happen during this period.
            response = urllib2.urlopen(req)
        except:
            # KMS server not available or network error happens.
            print 'communication error'
            return None
        else:
            return response

    def login(self, username, password):
        '''
        send login request to KMS server
        '''
        url = CONFIG.SERVER_URL + 'login'
        values = {'username': username, 'password': password}

        response = self.send_request_to_server(url, values)
        doc_keychain = 0
        if response:
            res = json.loads(response.read())
            if res['token'] != CONFIG.FAILED_LOGIN_TOKEN:
                doc_keychain = self.download_doc_keychain(username, password, res['token'])

            return res['token'], res['pub_key'], res['priv_key'], doc_keychain
        
        else:
            return None, None, None, None
    def download_doc_keychain(self, username, password, token):
        
        '''
        send download doc keychain request to KMS server
        '''
        
        url = CONFIG.SERVER_URL + 'fetch_own_doc_keychain'
        values = {'username': username,
                    'password': password,
                    'token': token}

        response = self.send_request_to_server(url, values)
        if response:
            doc_keychain = json.loads(response.read())
        else:
            doc_keychain = None

        return doc_keychain

    def register(self, username, password, RSA_public_key, RSA_private_key):
        
        '''
        send registration request to KMS server
        '''
        
        url = CONFIG.SERVER_URL + 'register'
        
        values = {'username': username, 'password': password, 'RSA_pub_key':RSA_public_key, 'RSA_priv_key' : RSA_private_key}

        response = self.send_request_to_server(url, values)
        if response is None:
            return CONFIG.REGISTER_FAILED
        else:
            return response.read()

    def shared_file(self, username, password, token):
        
        '''
        send file sharing request to KMS server
        '''
        
        url = CONFIG.SERVER_URL + 'shared_file'
        values = {'username': username,
                    'password': password,
                    'token': token}

        response = self.send_request_to_server(url, values)
        res = response.read()
        if res:
            return json.loads(res)
        else:
            return None

    def delete_doc_keychain(self, username, password, token, doc_id):
        
        '''
        send deleting doc keychain request to KMS server
        '''
        
        url = CONFIG.SERVER_URL + 'delete'
        values = {'username': username,
                'password': password,
                'token': token,
                'doc_id': doc_id}

        response = self.send_request_to_server(url, values)

        return response

    def upload_doc_key(self, username, password, token, doc_id, doc_key):
        
        '''
        send upload single doc key request to KMS server
        '''
        
        url = CONFIG.SERVER_URL + 'upload_doc_key_chain'
        values = {'username': username,
                'password': password,
                'token': token,
                'doc_id': doc_id,
                'doc_key': doc_key}

        response = self.send_request_to_server(url, values)
        return response.read()

    def update_doc_keychain(self, username, password, token):
        return self.download_doc_keychain(username, password, token)

    def download_sharing_recipient_RSA_pub_key(self, username, password, token, sharing_recipient):
        
        '''
        send download sharing recipient RSA public key request to KMS server
        '''
        
        url = CONFIG.SERVER_URL + 'fetch_pub_key'
        values = {'username': username,
                   'password': password,
                    'token': token,
                    'share_to_user': sharing_recipient}

        response = self.send_request_to_server(url, values)

        if response != CONFIG.FETCH_PUBLIC_KEY_FAILED:
            return response
        else:
            return None

    def share_file(self, username, password, token, share_to_user, doc_id, doc_key, sharing_url, expires):
        
        '''
        send file sharing request to KMS server
        '''
        
        url = CONFIG.SERVER_URL + 'share'
        values = {'username' : username,
                   'password' : password,
                    'token' : token,
                    'share_to_user' : share_to_user,
                    'doc_id' : doc_id,
                    'doc_key' : doc_key,
                    'url' : sharing_url,
                    'expires' : expires
                    }

        response = self.send_request_to_server(url, values)

        res = response.read()
        if res == CONFIG.FILE_SHARING_SUCCEED or res == CONFIG.FILE_SHARING_EXISTED:
            return True
        else:
            return False
