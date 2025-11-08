import streamlit as st
import hmac, hashlib
from Crypto.Cipher import AES

from views.utils.crypto import poodle_attack

# Follow ciphertext block size as per client Alice, according to Advanced Encryption Standard (AES).
block_size = AES.block_size
InvalidMsg = "Server: HMAC invalid!"

# Create interface for attack
st.title("Eve's Control Page")
st.header("Intercepted Message")

if st.button("Intercept Message"):
    if (
        "ciphertext_username" and "iv_username" and "key_username" and
        "ciphertext_password" and "iv_password" and "key_password"
    ) in st.session_state:
        intercepted_ciphertext_username = st.session_state["ciphertext_username"]
        iv_username = st.session_state["iv_username"]
        key_username = st.session_state["key_username"]

        intercepted_ciphertext_password = st.session_state["ciphertext_password"]
        iv_password = st.session_state["iv_password"]
        key_password = st.session_state["key_password"]

        st.write("Intercepted username:", intercepted_ciphertext_username)
        st.write("Intercepted IV for username:", iv_username.hex())

        st.write("Intercepted password:", intercepted_ciphertext_password)
        st.write("Intercepted IV for password:", iv_password.hex())

    else:
        st.error("Incomplete information required for poodle attack")

if st.button("Launch Poodle Attack"):
    if (
        "ciphertext_username" and "iv_username" and "key_username" and
        "ciphertext_password" and "iv_password" and "key_password"
    ) in st.session_state:

        intercepted_ciphertext_username = st.session_state["ciphertext_username"]
        iv_username = st.session_state["iv_username"]
        key_username = st.session_state["key_username"]

        decrypted_username = b""
        decrypted_password = b""

        try:
            print("Decrypted username:")
            decrypted_username = poodle_attack(
                intercepted_ciphertext_username, 
                iv_username, 
                block_size, 
                key_username
            )
            if decrypted_username != InvalidMsg:
                st.success(f"Decrypted username: {decrypted_username.decode('utf-8')}")
        except Exception as e:
            st.error(f"Attack on username failed: {str(e)}")

        intercepted_ciphertext_password = st.session_state["ciphertext_password"]
        iv_password = st.session_state["iv_password"]
        key_password = st.session_state["key_password"]

        try:
            print("Decrypted password:")
            decrypted_password = poodle_attack(
                intercepted_ciphertext_password, 
                iv_password, 
                block_size, 
                key_password
            )
            if decrypted_password != InvalidMsg:
                st.success(f"Decrypted password: {decrypted_password.decode('utf-8')}")
        except Exception as e:
            st.error(f"Attack on password failed: {str(e)}")
    else:
        st.error("No message has been intercepted yet!")
