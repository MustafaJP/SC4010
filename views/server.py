import streamlit as st
import hmac, hashlib
from Crypto.Cipher import AES

from views.utils.crypto import cbc_decrypt

from typing import Union
InvalidMsg = "Server: HMAC invalid!"

decrypted_username: Union[bytes, str] = InvalidMsg
decrypted_password: Union[bytes, str] = InvalidMsg

block_size = AES.block_size

st.title("Server Page")

if st.button("Registration Logs"):
    if (
        "ciphertext_username" and "iv_username" and "key_username" and
        "ciphertext_password" and "iv_password" and "key_password"
    ) in st.session_state:
        ciphertext_username = st.session_state["ciphertext_username"]
        iv_username = st.session_state["iv_username"]
        key_username = st.session_state["key_username"]

        try:
            print("Decrypt username:")
            decrypted_username = cbc_decrypt(
                ciphertext_username, 
                key_username, 
                iv_username, 
                block_size
            )
        except Exception as e:
            st.error(f"Error in decryption: {e}")

        ciphertext_password = st.session_state["ciphertext_password"]
        iv_password = st.session_state["iv_password"]
        key_password = st.session_state["key_password"]

        try:
            print("Decrypt password:")
            decrypted_password = cbc_decrypt(
                ciphertext_password, 
                key_password, 
                iv_password, 
                block_size
            )
        except Exception as e:
            st.error(f"Error in decryption: {e}")

        if (decrypted_username != InvalidMsg and decrypted_password != InvalidMsg):
            st.markdown(
                f"""
                Username: `{decrypted_username.decode('utf-8')}`  
                Password: `{decrypted_password.decode('utf-8')}`
                """
            )
            st.success("Account credentials received and decrypted!")
        else:
            st.error("HMAC is invalid!")
    else:
        st.error("No account credentials received yet.")