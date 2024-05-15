from tkinter import *
from tkinter import messagebox
import socket
from tcp_by_size import *

IP = "127.0.0.1"
PORT = 12345

def show_input_error():
    messagebox.showerror(title="Error", message="Please fill in all the fields")

def show_connection_error():
    messagebox.showerror(title="Error", message="Connection Error Occured")

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


def initialize_connection():

    sock = socket.socket()
    try:
        sock.connect((IP, PORT))
        print("connection succeeded")
    except:
        return False

    return sock


def notify_exit(sock):

    msg = "EXIT"
    send_with_size(sock, msg)
    resp = recv_by_size(sock)
    if resp.split('~')[0] == 'EXTR':
        return True
    return False


def create_request(request_type, email, pw):

    request = ''

    if request_type == "login":
        request = f"LOGN~{email}~{pw}"
    elif request_type == "register":
        request = f"REGI~{email}~{pw}"

    return request


def handle_srvr_response(response):

    fields = response.split('~')
    code = fields[0]

    if code == 'LOGR':
        show_login_succeed()
    elif code == 'REGR':
        show_signup_succeed()
    elif code == 'ERRR':

        if fields[1] == '501':
            show_general_error()
        elif fields[1] == '502':
            show_register_error()



def login(sock):

    global email_login, pw_login

    email = email_login.get()
    pw = pw_login.get()

    if email != '' and pw != '':
        msg = create_request("login", email, pw)
        send_with_size(sock, msg)
        srvr_response = recv_by_size(sock)
        handle_srvr_response(srvr_response)
    else:
        show_input_error()


def sign_up(sock):

    global email_register, pw_reg, pw_conf

    email = email_register.get()
    pw = pw_reg.get()
    confirm_pw = pw_conf.get()

    if email != '' and pw != '' and confirm_pw != '':

        if pw == confirm_pw:  # make sure pw and confirm-pw match
           msg = create_request("register", email, pw)
           send_with_size(sock, msg)
           srvr_response = recv_by_size(sock)
           handle_srvr_response(srvr_response)
        else:
            show_pwconfirm_error()

    else:
        show_input_error()


def register_page(sock):

    global window, email_register, pw_reg, pw_conf

    # set window
    reg_win = Toplevel(window)
    reg_win.title("Sign Up")
    reg_win.geometry("420x210")
    reg_win.resizable(False, False)

    # registery input
    Label(reg_win, text="Email Address:").place(x=5, y=15)
    email_register = Entry(reg_win, width=67)
    email_register.place(x=5, y=35)

    Label(reg_win, text="Password:").place(x=5, y=60)
    pw_reg = Entry(reg_win, width=67, show='*')
    pw_reg.place(x=5, y=80)

    Label(reg_win, text="Confirm Password:").place(x=5, y=105)
    pw_conf = Entry(reg_win, width=67, show='*')
    pw_conf.place(x=5, y=125)

    Button(reg_win, text="Sign Up", width=57, command=lambda: sign_up(sock)).place(x=5, y=160)

    # block main window
    reg_win.grab_set()


def login_page(sock):

    global email_login, pw_login

    # login input
    Label(text="Email Address:").place(x=5, y=15)
    email_login = Entry(width=67)
    email_login.place(x=5, y=35)

    Label(text="Password:").place(x=5, y=60)
    pw_login = Entry(width=67, show='*')
    pw_login.place(x=5, y=80)

    Button(text="Login", width=57, fg='#0000FF', command=lambda: login(sock)).place(x=5, y=115)
    Button(text="Register", width=57, bg='#00FFFF', command=lambda: register_page(sock)).place(x=5, y=150)
    Button(text="Forgot password", width=57, fg='#FF0000').place(x=5, y=185)


def main():

    global window

    sock = initialize_connection()
    if sock != False:
        # initialize GUI
        window = Tk()
        window.title("Sign In")
        window.geometry("420x220")
        window.resizable(False, False)
        login_page(sock)
        window.mainloop()

        # Close connection on finish
        if notify_exit(sock):
            sock.close()
            print("Disconnected")
    
    else:
        show_connection_error()


if __name__ == "__main__":
    main()