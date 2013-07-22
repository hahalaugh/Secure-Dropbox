from UI import SecureDropbox_UI
import traceback

if __name__ == '__main__':
    secure_dropbox_UI = SecureDropbox_UI()
    try:
        secure_dropbox_UI.start()
    except:
        print traceback.format_exc()
