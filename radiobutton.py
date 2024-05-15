from tkinter import *

var = None
transfer_method = None

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


choose_transfer_method()
print(transfer_method)