# secure_data_app.py

import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Setup encryption key
if 'key' not in st.session_state:
    st.session_state['key'] = Fernet.generate_key()
    st.session_state['cipher'] = Fernet(st.session_state['key'])

# Setup in-memory data storage and attempt counter
if 'stored_data' not in st.session_state:
    st.session_state['stored_data'] = {}

if 'failed_attempts' not in st.session_state:
    st.session_state['failed_attempts'] = 0

# Hashing function
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encryption
def encrypt_data(text):
    return st.session_state['cipher'].encrypt(text.encode()).decode()

# Decryption
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)

    for data_key, value in st.session_state['stored_data'].items():
        if value['encrypted_text'] == encrypted_text:
            if value['passkey'] == hashed_passkey:
                st.session_state['failed_attempts'] = 0  # Reset on success
                return st.session_state['cipher'].decrypt(encrypted_text.encode()).decode()
    
    # If no match
    st.session_state['failed_attempts'] += 1
    return None

# ----------------------------- Streamlit UI -----------------------------

st.set_page_config(page_title="Secure Data App", page_icon="🔒")

st.title("🔒 Secure Data Encryption System")

# Sidebar Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("📋 Navigation", menu)

# ----------------------------- Home Page -----------------------------
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data Storage System")
    st.markdown("""
    - 🔐 **Encrypt and Save** your sensitive information.
    - 🔓 **Retrieve your data** securely using your secret passkey.
    - 🛡️ **Security enforced** with passkey protection and login after 3 failed attempts.
    """)

# ----------------------------- Store Data Page -----------------------------
elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")

    with st.form("store_form"):
        user_data = st.text_area("Enter the data you want to secure:")
        passkey = st.text_input("Set a Passkey:", type="password")
        submit = st.form_submit_button("Encrypt & Save")

    if submit:
        if user_data and passkey:
            encrypted_text = encrypt_data(user_data)
            hashed_passkey = hash_passkey(passkey)
            st.session_state['stored_data'][encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            st.success("✅ Data encrypted and stored securely!")
        else:
            st.error("⚠️ Please fill in both fields.")

# ----------------------------- Retrieve Data Page -----------------------------
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Secure Data")

    if st.session_state['failed_attempts'] >= 3:
        st.warning("🔒 Too many failed attempts! Redirecting to Login...")
        st.switch_page("Login")  # Auto redirect if needed (Streamlit 1.25+)
    
    with st.form("retrieve_form"):
        encrypted_text = st.text_area("Paste Your Encrypted Text:")
        passkey = st.text_input("Enter Your Passkey:", type="password")
        retrieve = st.form_submit_button("Decrypt")

    if retrieve:
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)
            if decrypted_text:
                st.success(f"✅ Your Decrypted Data: \n\n{decrypted_text}")
            else:
                remaining = 3 - st.session_state['failed_attempts']
                st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")

                if st.session_state['failed_attempts'] >= 3:
                    st.warning("🔒 Too many failed attempts! Please login again.")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Please fill in both fields.")

# ----------------------------- Login Page -----------------------------
elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")

    with st.form("login_form"):
        master_password = st.text_input("Enter Master Password:", type="password")
        login = st.form_submit_button("Login")

    if login:
        if master_password == "admin123":  # Demo master password
            st.session_state['failed_attempts'] = 0
            st.success("✅ Login successful! You can now retrieve data again.")
            st.balloons()
        else:
            st.error("❌ Incorrect master password! Try again.")

