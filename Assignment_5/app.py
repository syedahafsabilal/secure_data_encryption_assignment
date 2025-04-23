import streamlit as st
st.set_option('server.enableCORS', False)
import hashlib
from cryptography.fernet import Fernet
from security import encrypt_data, decrypt_data, hash_passkey
from  data_persistence import load_data, save_data
from  multi_user_system import login_user

key =  b'DpvC5Z5Bg-SKQAKlEoWk0hLRbK_MwWyYNuQ6vR7StXc='
cipher = Fernet(key)

if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "is_logged_in" not in st.session_state:
    st.session_state.is_logged_in = False

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()
def decrypt_data(encrypted_text,passkey):
    hashed = hash_passkey(passkey)
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
st.title("Secure Data Encryption System")

menu = ["Home","Store Data","Retrieve Data","Login"]
choice = st.sidebar.selectbox("Navigate", menu)

if choice == "Home":
    st.subheader("Welcome")
    st.write("Encrypt and store your data securely.Retrieve it using your passkey")
elif choice == "Store Data":
    st.subheader("Store Data")
    user_data = st.text_area("Enter your data:")
    passkey = st.text_input("Enter a passkey:", type="password")
    if st.button("Encrypt & Store"):
       if user_data and passkey:
           encrypted = encrypt_data(user_data)
           hashed_pass = hash_passkey(passkey)
           st.session_state.stored_data[encrypted]={"encrypted_text": encrypted, "passkey": hashed_pass}
           st.success("Data stored successfully!")
           st.code(encrypted, language='test')
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
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"Incorrect passkey. Attempts left: {attempts_left}")
                if st.session_state.failed_attempts >= 3:
                    st.session_state.is_logged_in = False  
                    st.warning("Too many failed attempts.Redirecting to Login page")
                    st.experimental_rerun()
    else:
        st.error("Please fill in all fields")
elif choice =="Login":
    st.subheader("Login")
    master_key = st.text_input("Enter master key to continue:", type="password")
    if st.button("Login"):
        if master_key:
           if master_key == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.is_logged_in = True
            st.success("Login successful! You can now retrieve data.")
            st.experimental_rerun()
        else:
            st.error("Incorrect master password")
    else:
        st.error("Please enter the master key to login.")
