def login_user(username, password):
    if username in st.session_state.stored_data:
        stored_hashed_password = st.session_state.stored_data[username]["password"]
        if stored_hashed_password == hash_passkey(password):
            st.session_state.is_logged_in = True
            st.session_state.current_user = username
            return True
    return False