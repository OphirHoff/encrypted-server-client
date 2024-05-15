import pickle, hashlib, bcrypt, os
import datetime

DB_FILE = "users.pkl"
PEPPER = b'#K@(JJJFCS5D'

# indexes
PW = 0
SALT = 1
CODE = 2

code_expiry = 1  # minutes


class Database:
    def __init__(self):

        if not os.path.isfile(DB_FILE):
            create_db_file()
        
        self.data = load_data()
    
    def is_user_exist(self, email):

        if email in self.data:
            if self.is_code_expired(email):
                self.delete_user(email)
                return False
            return True

        return False
    
    def is_password_ok(self, email, password):
        salt = self.data[email][SALT]
        return self.data[email][PW] == hashlib.sha256(password.encode()+salt+PEPPER).hexdigest()

    def is_code_ok(self, email, code):
        if self.data[email][CODE] != '':
            print(self.data[email][CODE][0] == code)
            return self.data[email][CODE][0] == code
        return False

    def get_code(self, email):
        if self.data[email][CODE] != '':
            return self.data[email][CODE][0]
        return False
    
    def save_user(self, email, password, verf_code):

        if not self.is_user_exist(email):
            hashed_pw = salt_and_hash(password)
            self.data[email] = hashed_pw
            exp_time = datetime.datetime.now() + datetime.timedelta(minutes=code_expiry)
            self.data[email].append((verf_code, exp_time))
        else:
            return False

    def reset_password(self, email, new_password):
        hashed_pw, salt = salt_and_hash(new_password)
        self.data[email][PW] = hashed_pw
        self.data[email][SALT] = salt

    def update_securitycode(self, email, code):
        exp_time = datetime.datetime.now() + datetime.timedelta(minutes=code_expiry)
        self.data[email][CODE] = (code, exp_time)

    def delete_user(self, email):
            del self.data[email]

    def is_code_expired(self, email):
        if self.data[email][CODE] != '':
            return self.data[email][CODE][1] < datetime.datetime.now()
        return False

    def waiting_for_verify(self, email):
        if self.data[email][CODE] != '':
            return self.data[email][CODE][1] > datetime.datetime.now()

    def reset_code_expiry(self, email):
        self.data[email][CODE] = ''

    def update(self):
        with open(DB_FILE, 'wb') as file:
            pickle.dump(self.data, file)

    def __str__(self):
        return str(self.data)
    

def load_data():
    with open(DB_FILE, 'rb') as file:
        data = pickle.load(file)
    return data


def create_db_file():
    data = {}
    with open(DB_FILE, 'wb') as file:
        pickle.dump(data, file)


def salt_and_hash(password):
    salt = bcrypt.gensalt()
    hashed_pw = hashlib.sha256(password.encode()+salt+PEPPER).hexdigest()
    return [hashed_pw, salt]
