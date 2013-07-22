import CONFIG
import json
import urllib2
import os
import M2Crypto

class KMS_Handler(object):
    def __init__(self, cryptor):
        self.cryptor = cryptor

    def send_request_to_server(self, url, values):
        try:
            data_raw = json.dumps(values)
            req = urllib2.Request(url, data_raw)
            response = urllib2.urlopen(req)
        except:
            print 'communication error'
            return None
        else:
            return response

    def login(self, username, password):
        url = CONFIG.SERVER_URL + 'login'
        values = {'username': username, 'password': password}

        response = self.send_request_to_server(url, values)
        doc_keychain = 0
        if response is not None:
            res = json.loads(response.read())
            if res['token'] != CONFIG.FAILED_LOGIN_TOKEN:
                doc_keychain = self.download_doc_keychain(username, password, res['token'])

        return res['token'], res['pub_key'], res['priv_key'], doc_keychain

    def download_doc_keychain(self, username, password, token):

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
        url = CONFIG.SERVER_URL + 'register'
        
        values = {'username': username, 'password': password, 'RSA_pub_key':RSA_public_key, 'RSA_priv_key' : RSA_private_key}

        response = self.send_request_to_server(url, values)
        if response is None:
            return CONFIG.REGISTER_FAILED
        else:
            return response.read()

    def shared_file(self, username, password, token):
        url = CONFIG.SERVER_URL + 'shared_file'
        values = {'username': username,
                    'password': password,
                    'token': token}

        response = self.send_request_to_server(url, values)
        if response:
            return json.loads(response.read())
        else:
            return None

    def delete_doc_keychain(self, username, password, token, doc_id):
        url = CONFIG.SERVER_URL + 'delete'
        values = {'username': username,
                'password': password,
                'token': token,
                'doc_id': doc_id}

        response = self.send_request_to_server(url, values)

        return response

    def upload_doc_key(self, username, password, token, doc_id, doc_key):
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

        if response.read() == CONFIG.FILE_SHARING_SUCCEED:
            return True
        else:
            return False
