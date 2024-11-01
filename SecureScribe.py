import streamlit as st
from streamlit_option_menu import option_menu
from cryptography.fernet import Fernet
import os
from datetime import datetime,timedelta
import matplotlib.pyplot as plt
import pandas as pd
import time
import re
import schedule
import pandas as pd
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import os
import base64

# Constants for key derivation
SALT = os.urandom(16)  # A random salt for key derivation
ITERATIONS = 100000

def derive_key(password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Function to generate a key from a password (Fernet uses a 32-byte key)
def get_key(password):
    """Generates a Fernet-compatible key from a password."""
    if isinstance(password, bytes):
        # If the password is already bytes, just pad and encode to 32 bytes
        key = base64.urlsafe_b64encode(password.ljust(32)[:32])
    else:
        # Convert string password to bytes and then pad it to 32 bytes
        key = base64.urlsafe_b64encode(password.ljust(32)[:32].encode())
    return key

# Ensure directories exist
def ensure_directory_exists(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

# Ensure 'encrypted' and 'notes' directories exist
ensure_directory_exists("encrypted")
ensure_directory_exists("notes")

# Function to generate a new Fernet key
def generate_key():
    return Fernet.generate_key()



# Function to encrypt file data using Fernet
def encrypt_file(file_data, password):
    """Encrypts the file data using Fernet symmetric encryption with a key derived from the password."""
    key = get_key(password)
    fernet = Fernet(key)
    
    # Encrypt the file data
    encrypted_data = fernet.encrypt(file_data)
    return encrypted_data

# Function to decrypt file data using Fernet
def decrypt_file(encrypted_data, password):
    """Decrypts the file data using Fernet symmetric encryption with a key derived from the password."""
    try:
        key = get_key(password)
        fernet = Fernet(key)

        # Decrypt the file data
        decrypted_data = fernet.decrypt(encrypted_data)
        return decrypted_data
    except Exception as e:
        raise ValueError("Decryption failed: incorrect password or data integrity compromised.")

# Function to parse activity log file and return a DataFrame
def parse_activity_log():
    data = {"Date": [], "Type": [], "File Name": [], "Size (bytes)": []}
    if os.path.exists("activity_log.txt"):
        with open("activity_log.txt", "r") as log_file:
            lines = log_file.readlines()
            for line in lines:
                parts = line.strip().split(" - ")
                if len(parts) >= 4:
                    data["Date"].append(parts[0])
                    data["Type"].append(parts[1])
                    data["File Name"].append(parts[2])
                    data["Size (bytes)"].append(parts[3].split(" ")[0])
    return pd.DataFrame(data)

# Log activity function with time and filtering options
def log_activity(activity):
    with open("activity_log.txt", "a") as log_file:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_file.write(f"{timestamp} - {activity}\n")



# Password validation function
def validate_password(password):
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*()_+-=]", password):
        return "Password must contain at least one special character."
    return None

# Streamlit App UI
st.set_page_config(page_title="SecureScribe", layout="centered", initial_sidebar_state="auto",menu_items={'About':''})

main_body_logo = "assets/icon.png"
logo = "assets/icon.png"

st.logo(logo,icon_image=main_body_logo)


st.markdown(
    """
<style>
       
 
[data-testid="stAppViewContainer"]{


          

}
[data-testid="stHeader"]{
background-color:rgb(0,0,0,0)
}
  


</style>
    """,unsafe_allow_html=True
)





# Sidebar Option Menu
with st.sidebar:
    st.markdown(
    """
    <h1 style="font-size: 26px;margin-top:-10px;">SecureScribe</h1>
    """, 
    unsafe_allow_html=True
)
    
    st.markdown(
    """
    <style>
    [data-testid="stSidebar"] {
        background-color: #272930; /* Adjust background color with transparency */
        

    }
    </style>
    """,
    unsafe_allow_html=True
)
  
    selected = option_menu(
       "",
        ["FileSecure", "NoteSafe","Bulk Encryption", "Analytics","Settings"],
        icons=["lock", "file-earmark-text","folder", "bar-chart","gear"],
        menu_icon="none",
        default_index=0,
        styles={
            "container":{
                "background-color":"#272930"
            },
        # Sidebar background color
          "icon": {
            "color": "#FFFFFF",             # White icon color
            "font-size": "20px",            # Adjust icon size
            "margin-right": "10px"},
        "nav-link": {"font-size": "16px", "text-align": "left", "margin": "4px 0px 4px 0px" },
        "nav-link-selected": {"background-color": "#B20C0C","font-weight": "normal"},
    }
    )

st.markdown(
    """
    <style>
    .sidebar .sidebar-content {
        background-color: #f0f0f0; /* Change this to your desired color */
    }
    </style>
    """,
    unsafe_allow_html=True
)



# Folder encryption example
def encrypt_folder(folder_path, output_folder_path, password):
    """Encrypts all files in a folder and saves them to the output folder."""
    if not os.path.exists(output_folder_path):
        os.makedirs(output_folder_path)

    # Encrypt all files in the specified directory
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        if os.path.isfile(file_path):
            with open(file_path, 'rb') as file:
                file_data = file.read()
                encrypted_data = encrypt_file(file_data, password)

                new_file_name = os.path.join(output_folder_path, f"{filename}.enc")
                with open(new_file_name, 'wb') as encrypted_file:
                    encrypted_file.write(encrypted_data)

                print(f"Encrypted file - {new_file_name}")
# Function to schedule encryption based on user input (daily, weekly, monthly)

def schedule_encryption(folder_path, output_folder_path, password, schedule_type):
    if schedule_type == "Daily":
        schedule.every().day.at("00:00").do(encrypt_folder, folder_path, output_folder_path, password)
    elif schedule_type == "Weekly":
        schedule.every().week.at("00:00").do(encrypt_folder, folder_path, output_folder_path, password)
    elif schedule_type == "Monthly":
        # Schedule to run daily and check if it's the first day of the month
        schedule.every().day.at("00:00").do(lambda: check_monthly(folder_path, output_folder_path, password))

    while True:
        schedule.run_pending()
        time.sleep(60)

def check_monthly(folder_path, output_folder_path, password):
    # Check if today is the desired day of the month (e.g., the 1st)
    if datetime.now().day == 1:  # Change '1' to any specific day you want
        encrypt_folder(folder_path, output_folder_path, password)

import streamlit as st
from cryptography.fernet import Fernet
import base64
import hashlib
from appwrite.client import Client
from appwrite.services.databases import Databases

# Initialize Appwrite client
client = Client()
client.set_endpoint('https://cloud.appwrite.io/v1')  # Your Appwrite Endpoint
client.set_project('66fbc4e20032495faeb6')  # Your project ID
client.set_key('standard_1cc8d18bc7758ffa27825ac1825101b42d25465e4e9ba2aa40fb64222ad2415353845adf91d9663fe3310662e96f7dc123056d16562fa8e53597965897481ac3133daf78ea1029421a42f166cab44ff3e2cdb9ee60f8666fde074e612dd233f4d49a330d9f56f2fe422071d7e0d03cdccea7088a472a859b30672d76e942a829')  # Your API key
databases = Databases(client)

# Helper functions
def get_key(password):
    """Generate a key from the password."""
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def encrypt_file(file_data, password):
    """Encrypt the file data using the provided password."""
    key = get_key(password)
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(file_data)
    return encrypted_data

def decrypt_file(encrypted_data, password):
    """Decrypt the file using the provided password."""
    key = get_key(password)
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data)

def store_encrypted_file_in_db(file_name, encrypted_data, password):
    """Store encrypted file in Appwrite database."""
    databases.create_document(
        database_id='66fbddf800147dc2f3cb',
        collection_id='66fbde0e0025c5e4f3b7',
        document_id='unique()',
        data={
            "original_filename": file_name,
            "file": base64.b64encode(encrypted_data).decode(),  # Store as base64 encoded string
            "password": password  # Store the raw password
        }
    )

def fetch_encrypted_files():
    """Fetch all encrypted files from the database."""
    return databases.list_documents(
        database_id='66fbddf800147dc2f3cb',
        collection_id='66fbde0e0025c5e4f3b7',
    )['documents']

def fetch_encrypted_file_data(file_name):
    """Fetch the encrypted file data from the database based on file name."""
    result = databases.list_documents(
        database_id='66fbddf800147dc2f3cb',
        collection_id='66fbde0e0025c5e4f3b7',
    )
    
    # Find the document with the matching filename
    for document in result['documents']:
        if document['original_filename'] == file_name:
            return document
    
    return None

def encrypt_and_store_files(files, password, new_filenames):
    """Encrypt files and store them in the database."""
    progress_bar = st.progress(0)
    for idx, file in enumerate(files):
        file_data = file.read()
        encrypted_data = encrypt_file(file_data, password)
        new_file_name = f"{new_filenames[file.name]}.enc"
        
        store_encrypted_file_in_db(new_file_name, encrypted_data, password)
        progress_bar.progress((idx + 1) / len(files))
    progress_bar.empty()
    st.success("Files encrypted and stored in the database.")

def decrypt_file_and_show(selected_file):
    """Decrypt the selected file using the provided password."""
    encrypted_file_data = fetch_encrypted_file_data(selected_file)

    if encrypted_file_data:
        encrypted_data = base64.b64decode(encrypted_file_data['file'])
        return encrypted_data, encrypted_file_data['password']
    else:
        st.error(f"File {selected_file} not found in the database.")
        return None, None

def delete_file_from_db(file_name, password):
    """Delete the specified file from the database if the password is correct."""
    document = fetch_encrypted_file_data(file_name)
    
    if document and document['password'] == password:
        databases.delete_document(
            database_id='66fbddf800147dc2f3cb',
            collection_id='66fbde0e0025c5e4f3b7',
            document_id=document['$id']
        )
        return True
    return False

# Function to show the delete dialog
@st.dialog("Delete File 🗑️")
def showDeleteDialog(file):
    """Show the delete confirmation dialog."""
    st.subheader(f"Delete {file}")

    # Create a password input field
    password = st.text_input("Enter Password to Confirm Deletion", type="password", placeholder="Enter password...")

    if st.button("Delete"):
        if delete_file_from_db(file, password):
            st.success(f"{file} has been deleted successfully!")
        else:
            st.error("Invalid password. Could not delete the file.")

@st.dialog("Decrypt 🔓")
def showDecryptDialog(file, dec_data, correct_password):
    """Show the decrypt dialog with password verification."""
    st.subheader(f"{file}")
    
    # Create a password input field
    password = st.text_input("Enter Password to Verify", type="password", placeholder="Enter password...")

    if st.button("Verify"):
        if password == correct_password:
            st.success("Password verified successfully!")
            decrypted_data = decrypt_file(dec_data, correct_password)  # Decrypt the data
            st.download_button("Download", decrypted_data, file_name=file[:-4])  # Remove .enc for the downloaded filename
        else:
            st.error("Invalid password. Please try again.")

# Helper function for encryption after dialog confirmation
def encrypt_files_after_confirmation(files, password, new_filenames, save_to_cloud):
    """Encrypt files and either store them in the cloud or give a download option."""
    progress_bar = st.progress(0)
    for idx, file in enumerate(files):
        file_data = file.read()
        encrypted_data = encrypt_file(file_data, password)
        new_file_name = f"{new_filenames[file.name]}.enc"
        
        if save_to_cloud:
            # Store the encrypted file in the cloud
            store_encrypted_file_in_db(new_file_name, encrypted_data, password)
            st.success(f"{new_file_name} has been encrypted and saved to the cloud.")
        else:
            # Provide a download button for the encrypted file
            st.download_button(
                label=f"Download {new_file_name}",
                data=encrypted_data,
                file_name=new_file_name
            )
        progress_bar.progress((idx + 1) / len(files))
    progress_bar.empty()

# Helper function for encryption after dialog confirmation
def encrypt_files_after_confirmation(files, password, new_filenames, save_to_cloud):
    """Encrypt files and either store them in the cloud or give a download option."""
    progress_bar = st.progress(0)
    for idx, file in enumerate(files):
        file_data = file.read()
        encrypted_data = encrypt_file(file_data, password)
        new_file_name = f"{new_filenames[file.name]}.enc"
        
        if save_to_cloud:
            # Store the encrypted file in the cloud
            store_encrypted_file_in_db(new_file_name, encrypted_data, password)
            st.success(f"Encrypted & stored in cloud.")
        else:
            # Directly download the encrypted file without showing an additional button
            if st.download_button(
                label="Encrypt File",
                data=encrypted_data,
                file_name=new_file_name
            ):
                st.success(f"Encrypted & downloaded in local.")
            

            

        progress_bar.progress((idx + 1) / len(files))
    progress_bar.empty()



# Function to show the encryption confirmation dialog
@st.dialog("Encrypt 🔒")
def show_encrypt_dialog(files, password, new_filenames):
    """Show dialog to confirm encryption and choose where to save."""
    st.subheader("Confirm Encryption Details")

    # Display file names and rename options
    for file in files:
        st.success(f"{new_filenames[file.name]}.enc")

    # Checkbox to decide whether to save to cloud
    save_to_cloud = st.checkbox("Save to Cloud?", value=True)

    # Conditional button display based on save_to_cloud checkbox
    if save_to_cloud:
        if st.button("Encrypt File"):
            encrypt_files_after_confirmation(files, password, new_filenames, save_to_cloud)
    else:
        
            encrypt_files_after_confirmation(files, password, new_filenames, save_to_cloud)



# Streamlit interface
if selected == "FileSecure":
    st.title("FileSecure📜")
   
    tab_selection = st.tabs(["Encrypt File", "Decrypt File"])

    # ** Encrypt File Tab ** 
    with tab_selection[0]:
        st.subheader("Encrypt Files🔒")
        st.write("Upload any file here that you want to encrypt.")
        files = st.file_uploader("Choose files to encrypt", accept_multiple_files=True, label_visibility="collapsed")

        if files and any(file.name.endswith('.enc') for file in files):
            st.error("One or more selected files have the '.enc' extension. Please select only unencrypted files.")
        else:
            if files:
                st.markdown("<b>Generated Password (You can edit):</b>", unsafe_allow_html=True)
                password = st.text_input("Generated Password (You can edit)", label_visibility="collapsed", type="password", placeholder="Set strong password...")

                new_filenames = {}
                for idx, file in enumerate(files):
                    st.markdown("<b>Rename File:</b>", unsafe_allow_html=True)
                    new_name = st.text_input(f"Rename {file.name} (without .enc)", label_visibility="collapsed", value=file.name, key=f"rename_{idx}")
                    new_filenames[file.name] = new_name

                if st.button("Encrypt Files"):
                    # Open dialog to confirm file encryption
                    show_encrypt_dialog(files, password, new_filenames)

    # ** Decrypt File Tab **    
    with tab_selection[1]:
        st.markdown(f"""
                    <div style='height:30px'></div>""", unsafe_allow_html=True)       

        # Fetch all encrypted files from the database
        encrypted_files = fetch_encrypted_files()
        # Show the list of encrypted files with "Decrypt" and "Delete" buttons
        for idx, encrypted_file in enumerate(encrypted_files):
            original_filename = encrypted_file['original_filename']
            col1, col2, col3 = st.columns([5, 1, 1])  # Create three columns
            with col1:
                st.markdown(f"""
                    <h5 style='font-size:18px'>{original_filename}</h5>""", unsafe_allow_html=True)    
            with col2:
                if st.button("Decrypt", key=f"decrypt_{idx}"):  # Button to trigger decryption with a unique key
                    # Get the encrypted data and password from the database
                    encrypted_data, correct_password = decrypt_file_and_show(original_filename)

                    if encrypted_data:
                        # Directly show the dialog for password verification
                        showDecryptDialog(file=original_filename, dec_data=encrypted_data, correct_password=correct_password)

            with col3:
                if st.button("🗑️", key=f"delete_{idx}"):  # Button to trigger deletion with a unique key
                    showDeleteDialog(file=original_filename)

# Notes Menu Tabs
elif selected == "NoteSafe":
    st.title("NoteSafe📒")
    tab_selection = st.tabs(["Create Note", "Decrypt Note"])

    # Create Note Tab
    with tab_selection[0]:
        st.subheader("Encrypt a Note🔒")
        note_title = st.text_input("Note Title",placeholder="Enter you note title...")
        note_content = st.text_area("Note Content",placeholder="Write content here...")
        password_placeholder = st.empty()

        if note_title and note_content:
            password = password_placeholder.text_input("Enter Password to Protect Note", type="password")
            if st.button("Save Note"):
                validation_error = validate_password(password)
                if validation_error:
                    st.error(validation_error)
                else:
                    key = get_key(password)
                    note_data = f"Title: {note_title}\nContent:\n{note_content}".encode()
                    encrypted_note_data = encrypt_file(note_data, key)
                    note_filename = f"notes/{note_title}.enc"
                    with open(note_filename, "wb") as note_file:
                        note_file.write(encrypted_note_data)
                    st.success("Note saved and encrypted successfully!")
                    log_activity(f"Encrypted file - {note_filename} - {len(note_data)} bytes")

                    st.download_button(
                        label=f"Download Encrypted Note: {note_title}.enc",
                        data=encrypted_note_data,
                        file_name=f"{note_title}.enc",
                        mime="application/octet-stream"
                    )

    # Decrypt Note Tab
    with tab_selection[1]:
        st.subheader("Decrypt Notes🔓")
        files = st.file_uploader("Choose encrypted notes to decrypt", type="enc", accept_multiple_files=True, label_visibility="collapsed")
        password_placeholder = st.empty()

        if files:
            password = password_placeholder.text_input("Enter Password for Note Decryption", type="password")
            if st.button("Decrypt Notes"):
                if not password:
                    st.error("Please enter a password to decrypt the notes.")
                else:
                    key = get_key(password)
                    progress_bar = st.progress(0)
                    for idx, file in enumerate(files):
                        file_data = file.read()
                        if file.name.endswith('.enc'):
                            try:
                                decrypted_data = decrypt_file(file_data, key)
                                st.success(f"Note {file.name} decrypted successfully!")
                                st.text_area("Decrypted Note Content", decrypted_data.decode())
                                log_activity(f"Decrypted file - {file.name} - {len(decrypted_data)} bytes")

                            except Exception as e:
                                st.error(f"Failed to decrypt the note {file.name}. Error: {e}")
                        progress_bar.progress((idx + 1) / len(files))
                    progress_bar.empty()

# In the Analytics Menu
elif selected == "Analytics":
    st.title("Analytics")

    # Date Range Selection
    st.subheader("Select Date Range")
    col1, col2 = st.columns(2)
    with col1:
        start_date = st.date_input("Start Date", value=datetime.now(), label_visibility="visible")
    with col2:
        end_date = st.date_input("End Date", value=datetime.now() + timedelta(days=1), label_visibility="visible")

    # Parse activity log data
    df = parse_activity_log()

    if not df.empty:
        # Filter the DataFrame by selected dates
        df["Date"] = pd.to_datetime(df["Date"])
        filtered_df = df[(df["Date"] >= pd.Timestamp(start_date)) & (df["Date"] <= pd.Timestamp(end_date))]

        # Create Tabs
        tab_summary, tab_encrypted, tab_decrypted = st.tabs(["Summary", "Encrypted Files", "Decrypted Files"])

       
            # Inside the Summary Tab
        # Inside the Summary Tab
        with tab_summary:
            st.subheader("Summary of Encrypted and Decrypted Files")

            if not df.empty:
        # Group by date and count occurrences
                encrypted_counts = df[df["Type"] == "Encrypted file"].groupby(df["Date"].dt.date).size()
                decrypted_counts = df[df["Type"] == "Decrypted file"].groupby(df["Date"].dt.date).size()

        # Convert counts to DataFrame for plotting
                summary_df = pd.DataFrame({
                    "Encrypted": encrypted_counts,
                    "Decrypted": decrypted_counts
                }).fillna(0)

        # Use Streamlit's bar chart
                st.bar_chart(summary_df,color=['#6C1A1A', '#FF0000'])

            else:
                st.write("No activity log available to summarize.")

        


        with tab_encrypted:
            encrypted_df = filtered_df[filtered_df["Type"] == "Encrypted file"]
            if not encrypted_df.empty:
                st.subheader("Encrypted Files")
                encrypted_df["File Name"] = encrypted_df["File Name"].str.replace('.enc', '', regex=False)  # Remove .enc extension
                st.dataframe(encrypted_df[["Date", "File Name", "Size (bytes)"]])
            else:
                st.write("No encrypted files found in this date range.")

        with tab_decrypted:
            decrypted_df = filtered_df[filtered_df["Type"] == "Decrypted file"]
            if not decrypted_df.empty:
                st.subheader("Decrypted Files")
                decrypted_df["File Name"] = decrypted_df["File Name"].str.replace('.enc', '', regex=False)  # Remove .enc extension
                st.dataframe(decrypted_df[["Date", "File Name", "Size (bytes)"]])
            else:
                st.write("No decrypted files found in this date range.")
    else:
        st.write("No activity log available.")


# Settings Menu
elif selected == "Settings":
    st.title("Settings")

    # Settings Tabs
    tab_general, tab_encryption, tab_key_mgmt, tab_password, tab_about = st.tabs(["General", "Encryption", "Key Management", "Password","About"])

    # General Tab
    with tab_general:
        st.subheader("General Settings")
        # Option for enabling/disabling dark mode
        dark_mode = st.checkbox("Enable Dark Mode", value=False)
        if dark_mode:
            st.write("Dark mode enabled.")
        else:
            st.write("Dark mode disabled.")
        
        # Option for enabling notifications
        notifications = st.checkbox("Enable Notifications", value=True)
        if notifications:
            st.write("Notifications enabled.")
        else:
            st.write("Notifications disabled.")

    # Encryption Settings Tab
    with tab_encryption:
        st.subheader("Encryption Settings")

        # Option to select encryption algorithm
        encryption_algorithm = st.selectbox(
            "Select Encryption Algorithm",
            options=["Fernet (AES-128)", "AES-256", "ChaCha20"],
            index=0
        )
        st.write(f"Selected encryption algorithm: {encryption_algorithm}")

        # Option for file extension customization
        file_extension = st.text_input("Encrypted File Extension", value=".enc")
        st.write(f"Using file extension: {file_extension}")

        # Option for compression before encryption
        compress_before_encrypt = st.checkbox("Compress files before encryption", value=False)
        if compress_before_encrypt:
            st.write("Compression enabled before encryption.")
        else:
            st.write("Compression disabled.")

    # Key Management Tab
    with tab_key_mgmt:
        st.subheader("Key Management")

        # Option to change key file location
        st.write("Current Key Location: ./fernet_key.key")
        key_location = st.text_input("Change Key File Location", value="./fernet_key.key")
        if st.button("Update Key Location"):
            st.success(f"Key file location updated to: {key_location}")

        # Option for automatic key rotation
        auto_key_rotation = st.checkbox("Enable Automatic Key Rotation", value=False)
        if auto_key_rotation:
            rotation_interval = st.slider("Key Rotation Interval (in days)", 30, 365, 90)
            st.write(f"Automatic key rotation every {rotation_interval} days.")

        # Option for manual key regeneration
        if st.button("Generate New Encryption Key"):
            new_key = generate_key()
            st.success("New encryption key generated successfully.")
            with open(key_location, "wb") as file:
                file.write(new_key)

    # Password Settings Tab
    with tab_password:
        st.subheader("Password Settings")

        # Option to set default password length for generated passwords
        default_password_length = st.slider("Default Password Length", 8, 32, 12)
        st.write(f"Default password length: {default_password_length} characters.")

        # Option to include special characters in passwords
        special_chars = st.checkbox("Include Special Characters in Passwords", value=True)
        if special_chars:
            st.write("Special characters will be included in generated passwords.")
        else:
            st.write("Special characters will not be included.")

        # Option to set password expiration time
        password_expiration = st.checkbox("Enable Password Expiration", value=False)
        if password_expiration:
            expiration_days = st.slider("Password Expiration Time (in days)", 30, 180, 90)
            st.write(f"Passwords will expire after {expiration_days} days.")

    with tab_about:
        st.header("Encrypto")
        st.subheader("Keep your files safe and locked without any risk")
        st.write("Version 1.0.0")
        st.markdown("<p>Built and developed by Pranav</p>",unsafe_allow_html=True)
        

# In the Schedule Encrypt section of the Streamlit app
elif selected == "Bulk Encryption":
    st.title("Bulk Encryption")
    tab_selection = st.tabs(["Bulk Encrypt", "Bulk Decrypt"])

    # Schedule Encryption Tab
    with tab_selection[0]:
        st.subheader("Select Folder for Encryption")
        folder_path = st.text_input("Enter the folder path you want to encrypt",placeholder="ParentDirectory\ChlidDirectory")

        # Output Directory Selection for Encrypted Files
        output_folder_path = st.text_input("Enter the output folder path for encrypted files",placeholder="ParentDirectory\ChlidDirectory")

        # Password Input for Encryption
        password = st.text_input("Enter Encryption Password", type="password",placeholder="Set strong password...")

        if st.button("Encrypt Folder"):
            if not os.path.exists(folder_path):
                st.error("The specified folder path does not exist.")
            elif not os.path.exists(output_folder_path):
                st.error("The specified output folder path does not exist.")
            elif not password:
                st.error("Please provide a password for encryption.")
            else:
                # Call your scheduling function here
                schedule_encryption(folder_path, output_folder_path, password)
                st.success(f"Encryption scheduled for folder {folder_path} with output to {output_folder_path}.")

    # Bulk Decrypt Tab
    with tab_selection[1]:
        st.subheader("Bulk Decrypt Files")

        # Input for folder containing encrypted files
        decrypt_folder_path = st.text_input("Enter the folder path containing encrypted files for decryption",placeholder="ParentDirectory\ChlidDirectory")
        
        # Output Directory Selection for Decrypted Files
        decrypt_output_folder_path = st.text_input("Enter the output folder path for decrypted files",placeholder="ParentDirectory\ChlidDirectory")
        
        # Password Input for Decryption
        decrypt_password = st.text_input("Enter Decryption Password", type="password",placeholder="Enter your password...")
        
        if st.button("Decrypt Folder"):
            if not os.path.exists(decrypt_folder_path):
                st.error("The specified folder path does not exist.")
            elif not os.path.exists(decrypt_output_folder_path):
                st.error("The specified output folder path does not exist.")
            elif not decrypt_password:
                st.error("Please provide a password for decryption.")
            else:
                key = get_key(decrypt_password)
                decrypted_files = []
                progress_bar = st.progress(0)
                
                # Decrypt all files in the specified directory
                for filename in os.listdir(decrypt_folder_path):
                    if filename.endswith('.enc'):
                        file_path = os.path.join(decrypt_folder_path, filename)
                        with open(file_path, 'rb') as file:
                            encrypted_data = file.read()
                            try:
                                decrypted_data = decrypt_file(encrypted_data, key)
                                new_file_name = os.path.join(decrypt_output_folder_path, filename[:-4])  # Remove .enc extension
                                with open(new_file_name, 'wb') as decrypted_file:
                                    decrypted_file.write(decrypted_data)
                                decrypted_files.append(new_file_name)
                                log_activity(f"Decrypted file - {new_file_name} - {len(decrypted_data)} bytes")
                                st.success(f"Decrypted {filename} successfully!")
                            except Exception as e:
                                st.error(f"Failed to decrypt {filename}. Error: {e}")

                progress_bar.progress(1)  # Set progress to complete
                progress_bar.empty()
