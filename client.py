import time
import tkinter
from tkinter import *
from tkinter import messagebox
import socket
from tcp_by_size import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pickle
import rsa

IP = "127.0.0.1"
PORT = 12345
KEY = b'Sixteen byte key'

var = None
transfer_method = None


def aes_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return iv, ciphertext


def aes_decrypt(key, iv, data):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data), AES.block_size)

def transfer_key(sock):
    send_with_size(sock, create_request("key"))
    response = get_srvr_response(sock)
    print(response)
    if handle_srvr_response(response) == "init_ok":
        return True
    return False


def create_encrypted_msg(msg):
    t = aes_encrypt(KEY, msg.encode())
    return pickle.dumps(t)


def get_srvr_response(sock, start=False):
    if not start:  # if not before key transfer method approval
        t = recv_by_size(sock, return_type=bytes)
        iv, encrypted = pickle.loads(t)
        decrypted_msg = aes_decrypt(KEY, iv, encrypted)
        return decrypted_msg.decode()
    else:
        resp = recv_by_size(sock)
        return resp


def initialize_connection():

    sock = socket.socket()
    try:
        sock.connect((IP, PORT))
        print("connection succeeded")
    except:
        return False

    return sock


def notify_exit(sock):

    send_with_size(sock, create_request("EXIT"))
    resp = get_srvr_response(sock)
    if resp.split('~')[0] == 'EXTR':
        return True
    return False


def show_input_error():
    messagebox.showerror(title="Error", message="Please fill in all the fields")


def show_connection_error():
    messagebox.showerror(title="Error", message="Connection Error Occured")

def show_keyexchange_error():
    messagebox.showerror(title="Error", message="Server does not support this key exchange method")

def show_general_error():
    messagebox.showerror(title="Error", message="A problem occured, try again.")


def show_login_succeed():
    messagebox.showinfo(title="Login Succeeded", message="You are now logged-in!")


def show_signup_succeed():
    messagebox.showinfo(title="Registration Succeeded", message="You are now signed-up!")


def show_pwconfirm_error():
    messagebox.showerror(title="Error", message="Passwords do not match")


def show_register_error():
    messagebox.showerror(title="Error", message="Couldn't sign you up, try again.")


def show_verification_error():
    messagebox.showerror(title="Error", message="Code Incorrect or expired. Try again.")


def show_code_resent():
    messagebox.showinfo(title="Password Resent", message="The code was sent again.")


def show_pwreset_succeed():
    messagebox.showinfo(title="Password Reset", message="Password was reset successfully")


def sel():

    global var, transfer_method

    if var.get() == 1:
        transfer_method = 'RSA'
    else:
        transfer_method = 'DH'


def choose_transfer_method():

    global var

    # # set window
    rb_win = Tk()
    rb_win.title("Choose key transfer method")
    rb_win.geometry("210x105")
    rb_win.resizable(False, False)

    # self.rb_win.grab_set()
    var = IntVar()
    R1 = Radiobutton(rb_win, text="RSA", variable=var, value=1, command=sel)
    R1.pack(anchor=W)
    R2 = Radiobutton(rb_win, text="Diffie-Hellman", variable=var, value=2, command=sel)
    R2.pack(anchor=W)

    rb_win.mainloop()


def create_request(request_type, *argv):

    request = ''

    if request_type == "rsa":
        request = "GKEY"
    elif request_type == "key":
        request = f"INIT~{KEY.decode()}"
        return request
    elif request_type == "login":
        request = f"LOGN~{argv[0]}~{argv[1]}"
    elif request_type == "register":
        request = f"REGI~{argv[0]}~{argv[1]}"
    elif request_type == "verify":
        request = f"VERR~{argv[0]}~{argv[1]}"
    elif request_type == "resend":
        request = f"RSND~{argv[0]}"
    elif request_type == "forgot":
        request = f"FORG~{argv[0]}"
    elif request_type == "reset":
        request = f"RSTR~{argv[0]}~{argv[1]}~{argv[2]}"
    elif request_type == "disconnect":
        request = "EXIT"

    return create_encrypted_msg(request)


def handle_srvr_response(response):

    fields = response.split('~')
    code = fields[0]

    if code == 'INOK':
        return "init_ok"
    elif code == 'LOGR':
        show_login_succeed()
    elif code == 'VERF':
        return "verify"
    elif code == 'REGR':
        show_signup_succeed()
        return "reg_ok"
    elif code == 'REST':
        return "reset"
    elif code == 'RSOK':
        show_pwreset_succeed()
        return "res_ok"
    elif code == 'ERRR':

        if fields[1] == '501':
            show_general_error()
        elif fields[1] == '502':
            show_register_error()
        elif fields[1] == '503':
            show_verification_error()
        elif fields[1] == '504':
            show_keyexchange_error()


class GUI:

    def __init__(self, sock, transfer_method):

        self.sock = sock
        self.transfer_method = transfer_method

        self.window = Tk()
        self.window.title("Sign In")
        self.window.geometry("420x220")
        self.window.resizable(False, False)

        # GUI input variables
        self.email_login = None
        self.pw_login = None
        self.email_register = None
        self.pw_reg = None
        self.pw_conf = None
        self.code_entry = None

    def initialize_gui(self):

        success = self.transfer_key()
        if not success:
            self.window.destroy()
            return
        self.login_page()
        self.window.mainloop()



    def transfer_key(self):

        if self.transfer_method != None:

            if self.transfer_method == "RSA":
                send_with_size(self.sock, "RSAA".encode())
                response = get_srvr_response(self.sock, start=True)
                if response == "RSAR":
                    send_with_size(self.sock, "GKEY".encode())
                    response = recv_by_size(self.sock, return_type=bytes)
                    public_key = pickle.loads(response[5:])
                    to_send = rsa.encrypt(create_request("key").encode(), public_key)
                    send_with_size(self.sock, to_send)
                    response = get_srvr_response(self.sock)
                    print(response)
                    if handle_srvr_response(response) == "init_ok":
                        return True
                    return False
                else:
                    handle_srvr_response(response)
                    return False

            elif self.transfer_method == "DH":
                send_with_size(self.sock, "DHAA".encode())
                response = get_srvr_response(self.sock, start=True)
                if response == "DHAR":
                    pass
                else:
                    handle_srvr_response(response)
                    return False

            else:
                print("Error")


    def login(self):

        email = self.email_login.get()
        pw = self.pw_login.get()

        if email != '' and pw != '':
            msg = create_request("login", email, pw)
            send_with_size(self.sock, msg)
            srvr_response = get_srvr_response(self.sock)
            r = handle_srvr_response(srvr_response)
        else:
            show_input_error()

    def sign_up(self):

        email = self.email_register.get()
        pw = self.pw_reg.get()
        confirm_pw = self.pw_conf.get()

        if email != '' and pw != '' and confirm_pw != '':

            if pw == confirm_pw:  # make sure pw and confirm-pw match
                msg = create_request("register", email, pw)
                send_with_size(self.sock, msg)
                srvr_response = get_srvr_response(self.sock)
                r = handle_srvr_response(srvr_response)

                if r == "verify":
                    self.verification_page()
            else:
                show_pwconfirm_error()

        else:
            show_input_error()

    def verify(self):
        code = self.code_entry.get()
        email = self.email_register.get()

        if code != '':
            msg = create_request("verify", email, code)
            send_with_size(self.sock, msg)
            srvr_response = get_srvr_response(self.sock)
            r = handle_srvr_response(srvr_response)

            if r == 'reg_ok':
                self.verf_win.destroy()
                self.reg_win.destroy()
        else:
            show_input_error()

    def resend_code(self):

        try:
            email = self.email_register.get()
        except:
            email = self.email_login.get()

        msg = create_request("resend", email)
        send_with_size(self.sock, msg)
        srvr_response = get_srvr_response(self.sock)
        r = handle_srvr_response(srvr_response)

        if r == 'verify':
            show_code_resent()

    def forgot_pw(self):

        email = self.email_login.get()
        if email != '':
            msg = create_request("forgot", email)
            send_with_size(self.sock, msg)
            srvr_response = get_srvr_response(self.sock)
            r = handle_srvr_response(srvr_response)

            if r == "reset":
                self.reset_pw_page()

        else:
            show_input_error()

    def reset_pw(self):
        code = self.reset_code_entry.get()
        email = self.email_login.get()
        new_password = self.pw_reset.get()
        confirm_pw = self.pw_conf.get()

        if code != '' and email != '' and new_password:
            if new_password == confirm_pw:
                msg = create_request("reset", email, code, new_password)
                send_with_size(self.sock, msg)
                srvr_response = get_srvr_response(self.sock)
                r = handle_srvr_response(srvr_response)
                if r == 'res_ok':
                    self.reset_win.destroy()
            else:
                show_pwconfirm_error()
        else:
            show_input_error()

    def reset_pw_page(self):

        # set window
        self.reset_win = Toplevel(self.window)
        self.reset_win.title("Reset Password")
        self.reset_win.geometry("420x220")
        self.reset_win.resizable(False, False)

        Label(self.reset_win, text="Code:").place(x=5, y=15)
        self.reset_code_entry = Entry(self.reset_win, width=67)
        self.reset_code_entry.place(x=5, y=35)

        Label(self.reset_win, text="New Password:").place(x=5, y=60)
        self.pw_reset = Entry(self.reset_win, width=67, show='*')
        self.pw_reset.place(x=5, y=80)

        Label(self.reset_win, text="Confirm Password:").place(x=5, y=105)
        self.pw_conf = Entry(self.reset_win, width=67, show='*')
        self.pw_conf.place(x=5, y=125)

        Button(self.reset_win, text="Didn't receive a code", width=57, command=self.resend_code).place(x=5, y=155)
        Button(self.reset_win, text="Confirm", width=57, command=self.reset_pw).place(x=5, y=185)

        # block login page
        self.reset_win.grab_set()



    def verification_page(self):

        # set window
        self.verf_win = Toplevel(self.window)
        self.verf_win.title("Verification")
        self.verf_win.geometry("420x210")
        self.verf_win.resizable(False, False)

        Label(self.verf_win, text="Enter Code (valid a limited time):").place(x=5, y=15)
        self.code_entry = Entry(self.verf_win, width=67)
        self.code_entry.place(x=5, y=35)

        Button(self.verf_win, text="Didn't receive a code", width=57, command=self.resend_code).place(x=5, y=125)
        Button(self.verf_win, text="Confirm", width=57, command=self.verify).place(x=5, y=160)

        # block register window
        self.verf_win.grab_set()

    def register_page(self):

        # set window
        self.reg_win = Toplevel(self.window)
        self.reg_win.title("Sign Up")
        self.reg_win.geometry("420x210")
        self.reg_win.resizable(False, False)

        # registration input
        Label(self.reg_win, text="Email Address:").place(x=5, y=15)
        self.email_register = Entry(self.reg_win, width=67)
        self.email_register.place(x=5, y=35)

        Label(self.reg_win, text="Password:").place(x=5, y=60)
        self.pw_reg = Entry(self.reg_win, width=67, show='*')
        self.pw_reg.place(x=5, y=80)

        Label(self.reg_win, text="Confirm Password:").place(x=5, y=105)
        self.pw_conf = Entry(self.reg_win, width=67, show='*')
        self.pw_conf.place(x=5, y=125)

        Button(self.reg_win, text="Sign Up", width=57, command=self.sign_up).place(x=5, y=160)

        # block login window
        self.reg_win.grab_set()

    def login_page(self):

        # login input
        Label(text="Email Address:").place(x=5, y=15)
        self.email_login = Entry(width=67)
        self.email_login.place(x=5, y=35)

        Label(text="Password:").place(x=5, y=60)
        self.pw_login = Entry(width=67, show='*')
        self.pw_login.place(x=5, y=80)

        Button(text="Login", width=57, fg='#0000FF', command=self.login).place(x=5, y=115)
        Button(text="Register", width=57, bg='#00FFFF', command=self.register_page).place(x=5, y=150)
        Button(text="Forgot password", width=57, fg='#FF0000', command=self.forgot_pw).place(x=5, y=185)


def main():

    sock = initialize_connection()
    if sock != False:
        choose_transfer_method()
        gui = GUI(sock, transfer_method)
        gui.initialize_gui()

        # Close connection on finish
        if notify_exit(sock):
            sock.close()
            print("Disconnected")
    
    else:
        show_connection_error()


if __name__ == "__main__":
    main()