import streamlit as st
import hmac, hashlib
from Crypto.Cipher import AES
from Crypto import Random

from views.utils.crypto import cbc_encrypt  # xor/pad internal to module



# Define ciphertext block size and key size for encryption / decryption, according to Advanced Encryption Standard (AES).
block_size = AES.block_size
key_size = AES.key_size[2]

# Initialize session state variables
if ("ciphertext_username" and "key_username" and "iv_username") not in st.session_state:
    st.session_state["ciphertext_username"] = ""
    st.session_state["key_username"] = ""
    st.session_state["iv_username"] = ""

if ("ciphertext_password" and "key_password" and "iv_password") not in st.session_state:
    st.session_state["ciphertext_password"] = ""
    st.session_state["key_password"] = ""
    st.session_state["iv_password"] = ""

st.title("Account Registration Page")
st.text("First time user? Sign up for an account today!")

# Create a textbox for client to enter new account credentials
username_input = st.text_input("Username:", value="Alice")
password_input = st.text_input("Password:", value="Applied_Cryptography_ROCKS")

# Create a button to send the account credentials to the server browser
if st.button("Register"):
    secret_username = username_input.encode("utf-8")
    secret_password = password_input.encode("utf-8")

    iv_username = Random.new().read(block_size)
    key_username = Random.new().read(key_size)
    print("username key:", key_username)
    key_username_int = int.from_bytes(key_username, byteorder="big")
    print(key_username_int.bit_length(), "bits")

    iv_password = Random.new().read(block_size)
    key_password = Random.new().read(key_size)
    print("password key:", key_password)
    key_password_int = int.from_bytes(key_password, byteorder="big")
    print(key_password_int.bit_length(), "bits")

    ciphertext_username = b""
    ciphertext_password = b""

    print("Encrypt username:")
    try:
        ciphertext_username = cbc_encrypt(
            secret_username, 
            key_username, 
            iv_username, 
            block_size
        )
    except Exception as e:
        st.error(f"Error in decryption: {e}")

    st.session_state["ciphertext_username"] = ciphertext_username
    st.session_state["iv_username"] = iv_username
    st.session_state["key_username"] = key_username

    print("Encrypt password:")
    try:
        ciphertext_password = cbc_encrypt(
            secret_password, 
            key_password, 
            iv_password, 
            block_size
        )
    except Exception as e:
        st.error(f"Error in decryption: {e}")

    st.session_state["ciphertext_password"] = ciphertext_password
    st.session_state["iv_password"] = iv_password
    st.session_state["key_password"] = key_password

    st.success("Account registered successfully!")
    st.markdown(
    f"""
        \nYour username is: `{ciphertext_username}`  
        Your password is: `{ciphertext_password}`
    """
    )