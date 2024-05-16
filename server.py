import socket, pickle
import threading
from tcp_by_size import *
from database import *
from email_sender import *
import uuid
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import rsa
import shelve

IP = "0.0.0.0"
PORT = 12345
RSA_KEYS_SOURCE_FILE = 'rsa_keys'

# initialize & load DB
db = Database()

lock = threading.Lock()

rsa_public_key = None
rsa_private_key = None

EMAIL_TITLE = "Verification Code"
EMAIL_BODY = "Your verification code is: "


def load_rsa_keys(source_file):
    global rsa_public_key, rsa_private_key
    with shelve.open(source_file) as keys:
        rsa_public_key, rsa_private_key = keys['public'], keys['private']


def create_encrypted_msg(key, msg):
    t = aes_encrypt(key, msg.encode())
    return pickle.dumps(t)


def aes_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return iv, ciphertext


def aes_decrypt(key, iv, data):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data), AES.block_size)


def create_response(state, error=''):

    response = ""

    if state == "login":
        response = "LOGR"

    elif state == "verify":
        response = "VERF"

    elif state == "register":
        response = "REGR"

    elif state == "forgot":
        response = "REST"

    elif state == "reset":
        response = "RSOK"

    elif state == "error":
        response = f"ERRR~{error}"

    return response


def login_process(email, pw):

    if db.is_user_exist(email) and not db.waiting_for_verify(email) and db.is_password_ok(email, pw):
        return create_response("login")
    else:  # in case email doesnt exist or pw doesnt match
        return create_response("error", error='501')


def register_process(email, pw):

    with lock:
        if db.is_user_exist(email):
            return create_response("error", error=502)
        else:
            security_code = str(uuid.uuid4())[:8]
            db.save_user(email, pw, security_code)
            db.update()
            send_email(email, EMAIL_TITLE, EMAIL_BODY+security_code)
            print(security_code)
            return create_response("verify")


def verify_code(email, code):

    code_ok = db.is_code_ok(email, code) and not db.is_code_expired(email)

    if code_ok:
        db.reset_code_expiry(email)
        db.update()
        return create_response("register")
    else:
        return create_response("error", error=503)


def resend_code(email):

    security_code = db.get_code(email)
    if security_code:
        send_email(email, EMAIL_TITLE, EMAIL_BODY+security_code)
        print(security_code)
        return create_response("verify")
    else:
        return create_response("error", error=503)


def forgot_password(email):
    if db.is_user_exist(email):
        security_code = str(uuid.uuid4())[:8]
        send_email(email, EMAIL_TITLE, EMAIL_BODY+security_code)
        print(security_code)
        db.update_securitycode(email, security_code)
        return create_response("forgot")
    else:
        return create_response("error", error=501)


def reset_password(email, code, new_password):

    if db.is_user_exist(email):
        if db.is_code_ok(email, code) and not db.is_code_expired(email):
            db.reset_password(email, new_password)
            db.reset_code_expiry(email)
            return create_response("reset")
        else:
            return create_response("error", error=503)
    else:
        return create_response("error", error=501)


def handle_request(request):

    fields = request.split('~')
    code = fields[0]

    if code == "RSAA":
        return "RSAR"
    elif code == "DHAA":
        return create_response("error", error='504')
    elif code == "INIT":
        return "INOK"
    elif code == "LOGN":
        return login_process(fields[1], fields[2])
    elif code == "REGI":
        return register_process(fields[1], fields[2])
    elif code == "VERR":
        return verify_code(fields[1], fields[2])
    elif code == "RSND":
        return resend_code(fields[1])
    elif code == "FORG":
        return forgot_password(fields[1])
    elif code == "RSTR":
        return reset_password(fields[1], fields[2], fields[3])
    elif code == "EXIT":
        return "EXTR"


def get_client_request(sock, key):
    t = recv_by_size(sock, return_type=bytes)
    iv, encrypted = pickle.loads(t)
    decrypted_msg = aes_decrypt(key, iv, encrypted)
    return decrypted_msg.decode()


def initialize_connection_security(client, rsa_public_key, rsa_private_key):
    while True:
        request = recv_by_size(client, return_type=bytes)
        try:
            code = request.decode().split('~')[0]

            if code == "RSAA" or code == "DHAA":
                response = handle_request(request.decode())
                send_with_size(client, response.encode())

            elif code == "GKEY":
                send_with_size(client, b"KEYR~"+pickle.dumps(rsa_public_key))

        except:
            msg = rsa.decrypt(request, rsa_private_key)
            key = msg.split(b'~')[1]
            response = handle_request(msg.decode().split('~')[0])
            to_send = create_encrypted_msg(key, response)
            send_with_size(client, to_send)
            return key


def handle_client(client):

    # rsa_public_key, rsa_private_key = create_rsa_keys()
    global rsa_public_key, rsa_private_key

    # before key transfer
    key = initialize_connection_security(client, rsa_public_key, rsa_private_key)

    while True:
        request = get_client_request(client, key)
        if request != '':
            if request.split('~')[0] == "INIT":
                key = request.split('~')[1].encode()
            response = handle_request(request)
            if response != '' and key != b'':
                to_send = create_encrypted_msg(key, response)
                send_with_size(client, to_send)
            if response == 'EXTR':
                return


def main():

    load_rsa_keys(RSA_KEYS_SOURCE_FILE)

    server = socket.socket()
    server.bind((IP, PORT))
    server.listen()

    print("Running")

    client_threads = []
    while True:
        client,_ = server.accept()
        t = threading.Thread(target=handle_client, args=(client,))
        t.start()
        client_threads.append(t)

        if len(client_threads) > 10:
            break

    for thread in client_threads:
        thread.join()


if __name__ == "__main__":
    main()
