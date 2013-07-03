from dropbox import client, rest, session
import webbrowser

class DropboxHandler(object):
    def __init__(self):
        
        # application management information from Dropbox
        APP_KEY = '45th4wyk116kv8h'
        APP_SECRET = 'v62t0upm9ep89ov'
        ACCESS_TYPE = 'app_folder'
    
        # create a session handler by application information which could be inquired at dropbox application management page. 
        # access_type has two permissions, one for all folder access and 'app_folder' for specified folder access.
        
        sess = session.DropboxSession(APP_KEY, APP_SECRET, ACCESS_TYPE)
    
        # to get a request token from dropbox.
        request_token = sess.obtain_request_token()
        
        # generate a URL. the oauth_callback should be null since Secure Dropbox is not a web based application. so
        # no web page skip is required.   
        url = sess.build_authorize_url(request_token, oauth_callback = None)
        
        #user hint to open click the Allow button
        print "Please visit this website and press the 'Allow' button, then hit 'Enter' button here."
        
        # call the default Internet browser to open the URL.
        webbrowser.open(url)
        
        # after clicking Allow in the website, users are supposed to come back to the application and
        # do something to continue the procedure of login. 
        raw_input()
        
        # already get the request_token. Any request is to be sent via this token.  
        # Here the 2 step authorization mechanism of Dropbox is used. Application doesn't accept or record users information. 
        # The result of authentication is indicated by the received access_token.
        try: 
            access_token = sess.obtain_access_token(request_token)
        except rest.ErrorResponse:
            print 'authentication unsuccessful!'
            return None
        except Exception:
            print 'unknown exception happens!'
            return None
        
        #get the client handler after authentication success.
        client_handler = client.DropboxClient(sess)
        
        # show the welcome sentence
        info = repr(client_handler.account_info())
        print 'welcome to Secure Dropbox! '
        
        b  = client_handler.account_info()
        for a in client_handler.account_info():
            print a,b[a]
            
        self.dropbox_handler = client_handler
    
    def __delete__(self):
        self.dropbox_handler = None