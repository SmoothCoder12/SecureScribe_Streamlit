import base64
from datetime import datetime
import os
import pandas as pd
import streamlit as st
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import plotly.express as px
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from appwrite.client import Client
from appwrite.services.account import Account
from appwrite.services.databases import Databases
from appwrite.query import Query
from appwrite.services.users import Users
from appwrite.exception import AppwriteException
import uuid
import re
from streamlit_option_menu import option_menu  # Importing streamlit-option-menu

# Function to derive a key from the password
def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """ Derives a cryptographic key from the password using PBKDF2HMAC. """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes key length for Fernet
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Encrypt a file using a password (derived key)
def encrypt_file_with_password(file_path, password):
    salt = os.urandom(16)  # Random salt to ensure unique encryption key
    key = derive_key_from_password(password, salt)
    f = Fernet(key)

    # Read the file to be encrypted
    with open(file_path, 'rb') as file:
        file_data = file.read()

    # Encrypt the file data
    encrypted_data = f.encrypt(file_data)

    # Save the encrypted file with '.enc' extension
    encrypted_file_path = f"{file_path}.enc"
    with open(encrypted_file_path, 'wb') as file:
        # Write salt at the beginning of the encrypted file to use for decryption
        file.write(salt)
        file.write(encrypted_data)

    return encrypted_file_path, encrypted_data


# Decrypt a file using the password (derived key)
def decrypt_file_with_password(file_path, password):
    with open(file_path, 'rb') as file:
        # Extract the salt and encrypted data
        salt = file.read(16)  # First 16 bytes is the salt
        encrypted_data = file.read()

    # Derive the key from the password and salt
    key = derive_key_from_password(password, salt)
    f = Fernet(key)

    # Decrypt the file data
    decrypted_data = f.decrypt(encrypted_data)

    # Write the decrypted file (removing the '.enc' extension)
    decrypted_file_path = file_path.replace('.enc', '')
    with open(decrypted_file_path, 'wb') as file:
        file.write(decrypted_data)

    return decrypted_file_path

# Streamlit App UI
st.set_page_config(page_title="SecureScribe", layout="centered", initial_sidebar_state="auto")

# Appwrite Configuration
APPWRITE_ENDPOINT = "https://cloud.appwrite.io/v1"
PROJECT_ID = "6734c7d1003bd8f4748d"
API_KEY = "standard_95a3394882a21c61996988b665dc873f57c7582b6dcf807c6a7b433335a18cd83f65d6347b7594e70c1766425fc17dd58bf4cd1716ee85eac8c43563da5b261cb55845499f9738f060c32fdf7e5ae5b81462169b9e2329e9d3985ca061b69e288ce7fbb30d78addc0813f9ed319d6824561383c54d9674652dc91edb5389c35d"

# Initialize Appwrite client
client = Client()
client.set_endpoint(APPWRITE_ENDPOINT).set_project(PROJECT_ID).set_key(API_KEY)

# Initialize Account and Users services
account = Account(client)
users = Users(client)    
database = Databases(client)

st.markdown('''
<style>
            .st-emotion-cache-l7kopj {
    display: inline-flex;
    -webkit-box-align: center;
    align-items: center;
    -webkit-box-pack: center;
    justify-content: center;
    font-weight: 400;
    padding: 0.25rem 0.75rem;
    border-radius: 0.5rem;
    min-height: 2.5rem;
    margin: 0px;
    line-height: 1.6;
    color: inherit;
    width: 100%;
    cursor: pointer;
    user-select: none;
    background-color: rgb(178, 12, 12);
    border: 1px solid rgba(250, 250, 250, 0.2);
            
}

            
           @media (min-width: 476px) {
    .st-emotion-cache-13ln4jf {
        padding-left: 1rem;
        width: 580px;
        padding-right: 1rem;
    }
}
@media (min-width: 476px) {
    .st-emotion-cache-13ln4jf {
        padding-left: 1rem;
        width: 650px;
        padding-right: 1rem;
    }
}
            
            </style>
''',unsafe_allow_html=True)


# Streamlit App
def main():
    # Check if user is logged in
    if "session_id" not in st.session_state:
        st.markdown('''<h1 style="font-size: 95px;margin-top:-50px;text-align:center">SecureScribe</h1>''',unsafe_allow_html=True)
       
         # Show the title only for auth screen

    # Display tabs for login/signup if not logged in
    if "session_id" not in st.session_state:
        tab1, tab2 = st.tabs(["Login", "Signup"])

        with tab1:
            login_form()

        with tab2:
            signup_form()

    else:
        # If logged in, show the dashboard
        show_dashboard()

# Login Form
def login_form():
    st.header("Login")
    email = st.text_input("Email", key="login_email", placeholder="Enter your email")
    password = st.text_input("Password", type="password", key="login_password", placeholder="Enter your password")

    if st.button("Login",use_container_width=True):
        try:
            # Attempt to create a session using email and password
            session = account.create_email_password_session(email, password)

            # Store session data in session_state to track login status
            st.session_state["session_id"] = session["$id"]
            st.session_state["user_id"] = session["userId"]
            

            # Immediately redirect to dashboard by forcing a rerun
            st.rerun()

        except AppwriteException as e:
            st.error(f"Login failed: {e.message}")
            
            


# Signup Form
def signup_form():
    st.header("Signup")
    email = st.text_input("Email", key="signup_email", placeholder="Enter your email")
    password = st.text_input("Password", type="password", key="signup_password", placeholder="Create a password")
    name = st.text_input("Username", key="signup_name", placeholder="Choose a unique username")

    if st.button("Signup",use_container_width=True):
        try:
            # Check if a user with the same username already exists
            existing_users = users.list(queries=[Query.equal("name", name)])
            
            if existing_users["total"] > 0:
                st.error("Username already exists. Please choose a different username.")
                return  # Exit if username exists

            # Generate user_id from name
            user_id = generate_user_id_from_name(name)

            # Create user through Appwrite Users service
            user = users.create(user_id=user_id, email=email, password=password, name=name)
            
            st.success("Signup successful! You can now log in.")
        
        except AppwriteException as e:
            st.error(f"Signup failed: {e.message}")

# Function to generate user_id from the name
def generate_user_id_from_name(name):
    # Remove special characters, replace spaces with hyphens, and convert to lowercase
    user_id = re.sub(r'[^a-zA-Z0-9_-]', '', name.lower())
    
    # Make sure the length doesn't exceed 36 characters (Appwrite limit)
    if len(user_id) > 36:
        user_id = user_id[:36]

    # If the name results in an invalid user_id (empty), use a UUID instead
    if not user_id:
        user_id = str(uuid.uuid4())

    return user_id

# New screen/dashboard displayed after login
def show_dashboard():
   
    
    # Sidebar with options as an option menu (streamlit-option-menu)
    with st.sidebar:
        # Add the logo using st.logo (this will show the logo in the sidebar)
        st.logo("assets/icon.png")  # Make sure the logo path is correct
        st.markdown(
            """
            <h1 style="font-size: 24px;margin-top:-15px;">SecureScribe</h1>
            """, 
            unsafe_allow_html=True
        )
        selected = option_menu(
            menu_title="",  # Title is empty
            options=["File Encryption", "Analytics", "Settings"],  # Menu options (added Settings)
            icons=["key", "bar-chart", "gear"],  # Icons for each menu item
            menu_icon="cast",  # Icon for the menu
            default_index=0,  # Default option to be selected
            orientation="vertical",  # Vertical layout
            styles={
                "container": {
                    "background-color": "#161619"
                },
                "icon": {
                    "color": "#FFFFFF",  # White icon color
                    "font-size": "20px",  # Adjust icon size
                    "margin-right": "10px"
                },
                "nav-link": {
                    "font-size": "16px",
                    "text-align": "left",
                    "margin": "4px 0px 4px 0px"
                },
                "nav-link-selected": {
                    "background-color": "#B20C0C",
                    "font-weight": "normal"
                },
            }
        )

    if selected == "File Encryption":
        file_encryption()
    elif selected == "Analytics":
        show_analytics()
    elif selected == "Settings":
        show_settings()
   





def file_encryption():
    username = st.session_state.get("user_id","Guest")
    st.write(f"Welcome back, {username}!")
    st.markdown('''<h1 style="font-size: 60px;margin-top:-30px;margin-bottom:30px">File Encryption</h1>''',unsafe_allow_html=True)
    tab_selection = st.tabs(["Encrypt", "Decrypt", "Decrypt Local"])

    # ** Encrypt File Tab ** 
    with tab_selection[0]:
        
       
        files = st.file_uploader("Choose files to encrypt", accept_multiple_files=True, label_visibility="collapsed")

        if files and any(file.name.endswith('.enc') for file in files):
            st.warning("This file is already encrypted. Please choose files that have not been encrypted yet.")
            return
        
        if files:
            password = st.text_input("Set a password for encryption:")

            if password:
                save_to_cloud = st.checkbox("Save to Cloud?", value=False)

                for uploaded_file in files:
                    file_path = f"temp_{uploaded_file.name}"
                    with open(file_path, "wb") as f:
                        f.write(uploaded_file.read())

                    encrypted_file_path, encrypted_data = encrypt_file_with_password(file_path, password)

                    st.success(f"File encrypted successfully: {encrypted_file_path}")

                    with open(encrypted_file_path, "rb") as enc_file:
                        encrypted_data = enc_file.read()

                    st.download_button(
                        label="Download Encrypted File",
                        data=encrypted_data,
                        file_name=f"{uploaded_file.name}.enc",
                        mime="application/octet-stream",
                        use_container_width=True
                    )

                    if save_to_cloud:
                        try:
                            user_id = st.session_state.get("user_id", "unknown_user")
                            save_file_to_cloud(uploaded_file.name, encrypted_data, password, user_id)
                        except Exception as e:
                            st.error(f"Error saving to cloud: {e}")

                    os.remove(file_path)

    # ** Decrypt File Tab ** 
    with tab_selection[1]:
       
        
        try:
            user_id = st.session_state.get("user_id", None)
            if user_id:
                files = database.list_documents(
                    database_id="6735f95000204b39db40",
                    collection_id="6735fcf400273e1b4459",
                    queries=[Query.equal("user_id", user_id)]
                )
                
                if files["total"] == 0:
                    st.write("No encrypted files found.")
                else:
                    for file in files["documents"]:
                        file_name = file["original_filename"]
                        
                        with st.expander(file_name):
                            password_input = st.text_input("Enter password to decrypt:", type="password", key=f"decrypt_password_{file['$id']}")
                            
                            if st.button("Decrypt", key=f"decrypt_button_{file['$id']}"):
                                if password_input:
                                    try:
                                        encrypted_data = base64.b64decode(file["file"])
                                        encrypted_file_path = f"temp_{file_name}.enc"
                                        with open(encrypted_file_path, "wb") as f:
                                            f.write(encrypted_data)

                                        decrypted_file_path = decrypt_file_with_password(encrypted_file_path, password_input)
                                        st.success(f"File decrypted successfully: {decrypted_file_path}")

                                        with open(decrypted_file_path, "rb") as dec_file:
                                            decrypted_data = dec_file.read()

                                        st.download_button(
                                            label="Download Decrypted File",
                                            data=decrypted_data,
                                            file_name=file_name.replace(".enc", ""),
                                            mime="application/octet-stream",
                                            use_container_width=True
                                        )

                                        os.remove(encrypted_file_path)
                                        os.remove(decrypted_file_path)

                                    except Exception as e:
                                        st.error(f"Error during decryption: {e}")
                                else:
                                    st.warning("Please enter the password to decrypt the file.")
            else:
                st.write("You need to log in to see your files.")
        
        except Exception as e:
            st.error(f"Error fetching files: {e}")

    # ** Decrypt Local File Tab ** 
    with tab_selection[2]:
   

        local_file = st.file_uploader("Choose an encrypted file to decrypt", label_visibility="collapsed")
        
        if local_file:
            password_input = st.text_input("Enter password for decryption:", type="password")
            
            if st.button("Decrypt Local File"):
                if password_input:
                    try:
                        encrypted_file_path = f"temp_{local_file.name}"
                        with open(encrypted_file_path, "wb") as f:
                            f.write(local_file.read())

                        decrypted_file_path = decrypt_file_with_password(encrypted_file_path, password_input)
                        st.success(f"File decrypted successfully: {decrypted_file_path}")

                        with open(decrypted_file_path, "rb") as dec_file:
                            decrypted_data = dec_file.read()

                        st.download_button(
                            label="Download Decrypted File",
                            data=decrypted_data,
                            file_name=local_file.name.replace(".enc", ""),
                            mime="application/octet-stream",
                            use_container_width=True
                        )

                        os.remove(encrypted_file_path)
                        os.remove(decrypted_file_path)

                    except Exception as e:
                        st.error(f"Error during decryption: {e}")
                else:
                    st.warning("Please enter the password to decrypt the file.")


# Helper function to get encrypted files from the database
def get_files_from_cloud(user_id):
    try:
        # Query the database for the user's encrypted files
        documents = database.list_documents(
            database_id="6735f95000204b39db40",
            collection_id="6735fcf400273e1b4459",
             queries=[Query.equal('user_id', user_id)] # Filter by user_id
        )
        
        # Return the list of files
        return documents["documents"]
    except Exception as e:
        st.error(f"Error fetching files: {e}")
        return []
    
# Helper function to decrypt file from cloud
def decrypt_file_with_password_from_cloud(encrypted_file_data, password):
    try:
        # Decode the base64 encoded encrypted data
        encrypted_data = base64.b64decode(encrypted_file_data)

        # Extract the salt and encrypted data (if applicable)
        salt = encrypted_data[:16]  # Assuming salt is stored in the first 16 bytes
        encrypted_file_content = encrypted_data[16:]

        # Derive the key from the password and salt
        key = derive_key_from_password(password, salt)
        f = Fernet(key)

        # Decrypt the file content
        decrypted_data = f.decrypt(encrypted_file_content)
        return decrypted_data
    except Exception as e:
        st.error(f"Error during decryption: {str(e)}")
        return None


# Function to save file metadata and encrypted data to Appwrite Database
def save_file_to_cloud(file_name, encrypted_data, password, user_id):
    # Initialize Appwrite database service
    
    # Replace with your actual database ID
    database_id = "6735f95000204b39db40"  # Replace with your actual database ID
    
    try:
        # Base64 encode the encrypted file data
        encoded_file_data = base64.b64encode(encrypted_data).decode()  # Convert to base64 string
        upload_date = datetime.utcnow().isoformat()
        file_size = len(encrypted_data) / (1024 * 1024)  # Convert bytes to MB
        file_size = round(file_size, 2)  # Optionally, round to 2 decimal places


        # Create a document in the 'encrypted_files' collection
        document = database.create_document(
            database_id=database_id,  # Specify the database ID
            collection_id="6735fcf400273e1b4459",  # Replace with your collection ID
            document_id = str(uuid.uuid4()),  # Let Appwrite generate the document ID automatically
            data={
                "original_filename": file_name,
                "file": encoded_file_data,  # Store encrypted file data as base64 string
                "password": password,  
                "upload_date": upload_date,# Store raw password (not recommended)
                "file_size":file_size,  
                "user_id": user_id  # Store the user ID to associate the file with the user
            }
        )

        st.success(f"Encrypted file metadata saved to cloud with ID: {document['$id']}")
        return document  # Return the document object if needed for further reference

    except AppwriteException as e:
        st.error(f"Error saving file metadata to cloud: {e.message}")
        return None

def show_analytics():
    st.title("Analytics Dashboard")
    
    user_id = st.session_state.get("user_id", None)
    if user_id:
        try:
            # Fetch user's encrypted files from the database
            files = database.list_documents(
                database_id="6735f95000204b39db40",
                collection_id="6735fcf400273e1b4459",
                queries=[Query.equal("user_id", user_id)]
            )

            if files["total"] == 0:
                st.write("No encrypted files found.")
            else:
                # ** Total Files Encrypted **
                total_files = files["total"]
                st.metric("Total Encrypted Files", total_files)

                
        except Exception as e:
            st.error(f"Error fetching analytics data: {e}")
    else:
        st.write("You need to log in to view analytics.")



# Placeholder for settings
def show_settings():
    st.markdown('''<h1 style="font-size: 60px;margin-top:-30px;margin-bottom:30px">Settings</h1>''',unsafe_allow_html=True)

    


    st.write(f"Logout for your account {st.session_state["user_id"]} ?")
    if st.button("Logout", key="logout_button",use_container_width=True):
        logout()

# Logout function to clear session and return to login page
def logout():
    # Remove session data
    del st.session_state["session_id"]
    del st.session_state["user_id"]
    st.rerun()

if __name__ == "__main__":
    main()
