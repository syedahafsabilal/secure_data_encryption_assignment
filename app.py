import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet


def load_data():
    if os.path.exists("stored_data.json"):
        with open("stored_data.json") as f:
                return json.load(f)
    else:
        return {}

def save_data(data):
    with open("stored_data.json","w") as f:
        json.dump(data,f)

def generate_key():
    return Fernet.generate_key()

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()
    
def login_user(username, password):
    if username in st.session_state.users:
        stored_hashed_password = st.session_state.users[username]["password"]
        if stored_hashed_password == hash_passkey(password):
            st.session_state.is_logged_in = True
            st.session_state.current_user = username
            return True
    return False

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()
def decrypt_data(encrypted_text,key):
    hashed = hash_passkey(key)
    record = st.session_state.stored_data.get(encrypted_text)
    if record:
        if record["passkey"] == hashed:
           st.session_state.failed_attempts = 0
           return cipher.decrypt(encrypted_text.encode()).decode()
        else:
           st.session_state.failed_attempts += 1
           return None
    else:
        st.session_state.failed_attempts += 1
        return None
key =  b'DpvC5Z5Bg-SKQAKlEoWk0hLRbK_MwWyYNuQ6vR7StXc='
cipher = Fernet(key)

if "stored_data" not in st.session_state:
    st.session_state.stored_data = load_data()
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "is_logged_in" not in st.session_state:
    st.session_state.is_logged_in = False
if "users" not in st.session_state:
    st.session_state.users = {}
if "password" not in st.session_state:
     st.session_state.password = ""
save_data(st.session_state.stored_data)

st.title("Secure Data Encryption System")

menu = ["Home","Store Data","Retrieve Data","Login"]
choice = st.sidebar.selectbox("Navigate", menu)

if choice == "Home":
    st.subheader("Welcome")
    st.write("Encrypt and store your data securely.Retrieve it using your passkey")
elif choice == "Store Data":
    st.subheader("Store Data")

    if not st.session_state.is_logged_in:
        st.warning("Please login to store data")
        st.stop()
    user_data = st.text_area("Enter your data:")
    passkey = st.text_input("Enter a passkey(same as login password ):", type="password")
    store_btn = st.button("Encrypt & Store")
    if store_btn:
       if user_data and passkey:
           
           correct_hashed_password = st.session_state.users[st.session_state.current_user]["password"]
           if hash_passkey(passkey) == correct_hashed_password:
               if user_data:
                   encrypted = encrypt_data(user_data)
                   hashed_pass = hash_passkey(passkey)
                   st.session_state.stored_data[encrypted]={
                       "encrypted_text": encrypted,
                       "passkey": hashed_pass
                   }
                   save_data(st.session_state.stored_data)
                   st.success("Data stored successfully!")
                   st.code(encrypted, language='text')
                   st.session_state.failed_attempts = 0
               else:
                   st.error("Please enter some data to store")
           else:
              st.session_state.failed_attempts += 1
              attempts_left = 3 - st.session_state.failed_attempts
              if attempts_left > 0:
                 st.error(f"Incorrect password. Attempts left: {attempts_left}")
              else:
                 st.session_state.is_logged_in = False
                 st.session_state.failed_attempts = 0
                 st.error("Too many failed attempts. Redirecting to Home..")
                 st.stop()
    else:
        st.error("Please enter both data and passkey.")

        

elif choice == "Retrieve Data":
    st.subheader("Retrieve Data")

    if not st.session_state.is_logged_in:
        st.warning("Please login again to continue")
        st.stop()
    encrypted_input = st.text_area("Paste your encrypted data:")
    passkey_input = st.text_input("Enter your passkey:", type="password")
    if  st.button("Decrypt"):
         if encrypted_input and passkey_input:
            result = decrypt_data(encrypted_input,passkey_input)

            if result:
                st.success("Data Decrypted")
                st.code(result, language="text")
            else:
                st.session_state.failed_attempts += 1               
                attempts_left = 3 - st.session_state.failed_attempts
                if attempts_left > 0:
                    st.error(f"Incorrect passkey. Attempts left: {attempts_left}")
                else:
                    st.session_state.is_logged_in = False  
                    st.session_state.failed_attempts = 0
                    st.error("Too many failed attempts.Redirecting to Login page")  
                    st.stop()
                    
    else:
        st.error("Please fill in all fields")

elif choice =="Login":
    st.subheader("Login or Register")
    if "username" not in st.session_state:
        st.session_state.username = ""
    if "password" not in st.session_state:
        st.session_state.password = ""
    username = st.text_input("Username:",value=st.session_state.username)
    password = st.text_input("Password:",type="password",value=st.session_state.password)

    st.session_state.username = username
    st.session_state.password = password
    if st.button("Register"):
       if username and password:
          if username not in st.session_state.users:
               st.session_state.users[username] = {"password": hash_passkey(password)}
               st.success("User registered successfully!")
          else:
              st.warning("Username already exists.")
       else:
           st.error("Please fill in both fields.")
    if st.button("Login"):
       if login_user(st.session_state.username, st.session_state.password):
          st.success("Login successful!")
          st.stop()
       else:
           st.error("Invalid credentials.")