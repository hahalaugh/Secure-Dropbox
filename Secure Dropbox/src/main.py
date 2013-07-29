from UI import SecureDropbox_UI
import traceback

# SecureDropbox main Entrance
if __name__ == '__main__':
    
    # create a SecureDropbox instance
    secure_dropbox_UI = SecureDropbox_UI()
    
    try:
        
        # start the instance
        secure_dropbox_UI.start()
        
    except:
        print traceback.format_exc()
