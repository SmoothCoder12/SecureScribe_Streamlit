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

# Parse activity log file and return a DataFrame
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
                    data["Size (bytes)"].append(int(parts[3].split(" ")[0]))  # Ensure size is stored as integer
    # Convert to DataFrame and convert Date to datetime object
    df = pd.DataFrame(data)
    df["Date"] = pd.to_datetime(df["Date"], errors='coerce')
    return df

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
        background-color: #18181B; /* Adjust background color with transparency */
        

    }
    </style>
    """,
    unsafe_allow_html=True
)
  
    selected = option_menu(
       "",
        ["FileSecure", "Analytics"],
        icons=["lock","bar-chart"],
        menu_icon="none",
        default_index=0,
        styles={
            "container":{
                "background-color":"#18181B"
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






import streamlit as st
from cryptography.fernet import Fernet
import base64
import hashlib
from appwrite.client import Client
from appwrite.services.databases import Databases

# Initialize Appwrite client
client = Client()
client.set_endpoint('https://cloud.appwrite.io/v1')  # Your Appwrite Endpoint
client.set_project('6734c7d1003bd8f4748d')  # Your project ID
client.set_key('standard_95a3394882a21c61996988b665dc873f57c7582b6dcf807c6a7b433335a18cd83f65d6347b7594e70c1766425fc17dd58bf4cd1716ee85eac8c43563da5b261cb55845499f9738f060c32fdf7e5ae5b81462169b9e2329e9d3985ca061b69e288ce7fbb30d78addc0813f9ed319d6824561383c54d9674652dc91edb5389c35d')  # Your API key
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
        database_id='6734c8120021b85413f0',
        collection_id='6734c85900181a41edf0',
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
        database_id='6734c8120021b85413f0',
        collection_id='6734c85900181a41edf0',
    )['documents']

def fetch_encrypted_file_data(file_name):
    """Fetch the encrypted file data from the database based on file name."""
    result = databases.list_documents(
        database_id='6734c8120021b85413f0',
        collection_id='6734c85900181a41edf0',
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
            database_id='6734c8120021b85413f0',
            collection_id='6734c85900181a41edf0',
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


