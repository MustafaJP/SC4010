# conda activate chat-with-website
# streamlit run page_controller.py

import streamlit as st

# Server browser page
Server = st.Page(
    page="views/server.py",
    title="Server Page",
    icon=":material/dns:",
)

# Client browser page
Alice = st.Page(
    page="views/Alice.py",
    title="Account Registration Page",
    icon=":material/person:",
    default=True,
)

# Attacker browser page
Eve = st.Page(
    page="views/Eve.py",
    title="Eve's Control Page",
    icon=":material/security:",
)

# To go between the different pages
pg = st.navigation(pages=[Server, Alice, Eve]).run()
