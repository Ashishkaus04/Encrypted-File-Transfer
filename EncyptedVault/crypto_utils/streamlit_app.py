# ----------------------------------------------
#  Streamlit Encrypted Web3 IPFS Vault
#  AES + RSA + IPFS + Ganache Blockchain
#  Fully Upgraded Version (AUTO-HASH, CID lookup,
#  filename lookup, event scanner, decrypt)
# ----------------------------------------------

import streamlit as st
from pathlib import Path
import os
import json
import base64
import hashlib
import tempfile
from datetime import datetime, timezone
import requests

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from web3 import Web3
from ipfs_uploader import upload_to_ipfs

# --------------------------------
# CONFIG – UPDATE THESE
# --------------------------------
GANACHE_URL = "http://127.0.0.1:7545"
CONTRACT_ADDRESS = "0x03a56dFAaE443250846D225A89c24c42278c7A73"   # <---- CHANGE THIS

ABI_JSON = '''[
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": true,
				"internalType": "string",
				"name": "fileHash",
				"type": "string"
			},
			{
				"indexed": false,
				"internalType": "string",
				"name": "filename",
				"type": "string"
			},
			{
				"indexed": false,
				"internalType": "string",
				"name": "ipfsCid",
				"type": "string"
			},
			{
				"indexed": true,
				"internalType": "address",
				"name": "owner",
				"type": "address"
			},
			{
				"indexed": false,
				"internalType": "uint256",
				"name": "timestamp",
				"type": "uint256"
			}
		],
		"name": "FileStored",
		"type": "event"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "_filename",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "_fileHash",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "_encAesKeyB64",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "_ipfsCid",
				"type": "string"
			}
		],
		"name": "storeFileWithKeyAndCID",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "_fileHash",
				"type": "string"
			}
		],
		"name": "getFileWithKeyAndCID",
		"outputs": [
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			},
			{
				"internalType": "address",
				"name": "",
				"type": "address"
			},
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			},
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			}
		],
		"name": "records",
		"outputs": [
			{
				"internalType": "string",
				"name": "filename",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "fileHash",
				"type": "string"
			},
			{
				"internalType": "address",
				"name": "owner",
				"type": "address"
			},
			{
				"internalType": "uint256",
				"name": "timestamp",
				"type": "uint256"
			},
			{
				"internalType": "string",
				"name": "encAesKeyB64",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "ipfsCid",
				"type": "string"
			}
		],
		"stateMutability": "view",
		"type": "function"
	}
]'''

RSA_PUBLIC = "public.pem"
RSA_PRIVATE = "private.pem"

# -------------------------
# CRYPTO HELPERS
# -------------------------
def aes_encrypt_bytes(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct = cipher.encrypt(pad(plaintext, AES.block_size))
    return cipher.iv + ct

def aes_decrypt_bytes(blob, key):
    iv, ct = blob[:16], blob[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

def rsa_encrypt_key(aes_key, pub_path):
    pub = RSA.import_key(Path(pub_path).read_bytes())
    return PKCS1_OAEP.new(pub).encrypt(aes_key)

def rsa_decrypt_key(enc_key_bytes, priv_path):
    priv = RSA.import_key(Path(priv_path).read_bytes())
    return PKCS1_OAEP.new(priv).decrypt(enc_key_bytes)

def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()

# -------------------------
# WEB3 INIT
# -------------------------
w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
if not w3.is_connected():
    st.error("Cannot connect to Ganache")
    st.stop()

ABI = json.loads(ABI_JSON)
contract = w3.eth.contract(
    address=Web3.to_checksum_address(CONTRACT_ADDRESS),
    abi=ABI
)

ACCOUNT = w3.eth.accounts[0]

# -------------------------
# EVENT SCANNER
# -------------------------
def load_events():
    try:
        events = contract.events.FileStored().create_filter(from_block=0).get_all_entries()
        rows = []
        for evt in events:
            args = evt["args"]
            rows.append({
                "filename": args["filename"],
                "fileHash": args["fileHash"],
                "cid": args["ipfsCid"],
                "owner": args["owner"],
                "timestamp": datetime.fromtimestamp(args["timestamp"], timezone.utc).isoformat(),
                "tx": evt["transactionHash"].hex()
            })
        return rows
    except Exception as e:
        st.error("Event load error: " + str(e))
        return []

# -------------------------
# STREAMLIT UI
# -------------------------
st.set_page_config(page_title="Encrypted IPFS Vault", layout="wide")
st.title("🔐 Encrypted IPFS File Vault (AES + RSA + IPFS + Blockchain)")

col1, col2 = st.columns(2)

# ------------------------------------------------------------
# LEFT PANEL — UPLOAD & STORE
# ------------------------------------------------------------
with col1:

    st.header("⬆️ Upload → Encrypt → IPFS → Blockchain")

    uploaded = st.file_uploader("Choose a file")

    if uploaded:
        filename = uploaded.name
        data = uploaded.read()

        if st.button("Encrypt + Upload + Store"):
            try:
                aes_key = get_random_bytes(16)
                enc_blob = aes_encrypt_bytes(data, aes_key)

                encKeyBytes = rsa_encrypt_key(aes_key, RSA_PUBLIC)
                encKeyB64 = base64.b64encode(encKeyBytes).decode()

                # save encrypted temp file
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    tmp.write(enc_blob)
                    temp_path = tmp.name

                cid = upload_to_ipfs(temp_path)
                st.success("IPFS CID: " + cid)

                file_hash = sha256_bytes(enc_blob)
                st.success("FileHash: " + file_hash)

                tx_hash = contract.functions.storeFileWithKeyAndCID(
                    filename, file_hash, encKeyB64, cid
                ).transact({'from': ACCOUNT})

                w3.eth.wait_for_transaction_receipt(tx_hash)
                st.success("Stored in blockchain: " + tx_hash.hex())

                os.remove(temp_path)
                st.balloons()

            except Exception as e:
                st.error("Upload failed: " + str(e))

# # ------------------------------------------------------------
# # RIGHT PANEL — RETRIEVE & DECRYPT (FULL STATE PERSISTENCE)
# # ------------------------------------------------------------
# with col2:
#     st.header("📥 Retrieve & Decrypt (CID Recommended)")

#     # Initialize session state
#     if "retrieve_input" not in st.session_state:
#         st.session_state.retrieve_input = ""

#     if "retrieve_enc_blob" not in st.session_state:
#         st.session_state.retrieve_enc_blob = None

#     if "retrieve_metadata" not in st.session_state:
#         st.session_state.retrieve_metadata = None

#     if "retrieve_hash" not in st.session_state:
#         st.session_state.retrieve_hash = None

#     # TEXT INPUT (CID or fileHash)
#     user_input = st.text_input(
#         "Enter fileHash, CID, or byte list",
#         value=st.session_state.retrieve_input,
#         key="retrieve_input_box"
#     )

#     # SAVE INPUT
#     st.session_state.retrieve_input = user_input

#     # FETCH BUTTON
#     if st.button("Fetch Record", key="retrieve_fetch_btn"):

#         query = user_input.strip()

#         # CASE A — Byte array conversion
#         if "," in query:
#             try:
#                 nums = [int(x.strip()) for x in query.split(",")]
#                 query = hashlib.sha256(bytes(nums)).hexdigest()
#                 st.info("Converted byte-array → SHA256:\n" + query)
#             except:
#                 st.error("Invalid byte list format")
#                 st.stop()

#         # CASE B — CID (length > 64)
#         if len(query) > 64:
#             try:
#                 r = requests.get(f"https://ipfs.io/ipfs/{query}")
#                 if r.status_code == 200:
#                     enc_blob = r.content
#                     st.session_state.retrieve_enc_blob = enc_blob
#                     query = sha256_bytes(enc_blob)
#                     st.info("CID → SHA256 computed:\n" + query)
#                 else:
#                     st.error("Could not download from IPFS")
#                     st.stop()
#             except:
#                 st.error("CID download failed")
#                 st.stop()

#         # FINAL — now query is SHA256
#         try:
#             rec = contract.functions.getFileWithKeyAndCID(query).call()

#             if rec[0] == "":
#                 st.error("No blockchain record found for this hash")
#                 st.stop()

#             # Save metadata
#             st.session_state.retrieve_metadata = rec
#             st.session_state.retrieve_hash = query

#             # If we came from fileHash (not CID), we must download encrypted bytes
#             if st.session_state.retrieve_enc_blob is None:
#                 r = requests.get(f"https://ipfs.io/ipfs/{rec[5]}")
#                 if r.status_code != 200:
#                     st.error("Failed downloading encrypted file from IPFS")
#                     st.stop()
#                 st.session_state.retrieve_enc_blob = r.content

#             st.success("Record successfully loaded!")

#         except Exception as e:
#             st.error("Error: " + str(e))
#             st.stop()

#     # --------------------------
#     # SHOW METADATA IF AVAILABLE
#     # --------------------------
#     if st.session_state.retrieve_metadata is not None:
#         rec = st.session_state.retrieve_metadata
#         filename, fileHash, owner, ts, encKeyB64, cid = rec

#         st.write("**Filename:**", filename)
#         st.write("**CID:**", cid)
#         st.write("**FileHash:**", fileHash)
#         st.write("**Owner:**", owner)
#         st.write("**Timestamp:**", datetime.fromtimestamp(ts, timezone.utc).isoformat())

#         # --------------------------
#         # DECRYPT BUTTON (PERSISTENT)
#         # --------------------------
#         if st.button("🔓 Decrypt File", key="retrieve_decrypt_btn"):
#             try:
#                 enc_blob = st.session_state.retrieve_enc_blob

#                 # Step 1 — RSA decrypt AES key
#                 aes_key = rsa_decrypt_key(base64.b64decode(encKeyB64), RSA_PRIVATE)

#                 # Step 2 — AES decrypt data
#                 plain = aes_decrypt_bytes(enc_blob, aes_key)

#                 # Step 3 — download decrypted file
#                 st.download_button(
#                     "⬇️ Download Decrypted File",
#                     data=plain,
#                     file_name=f"decrypted_{filename}",
#                     key="retrieve_download_btn"
#                 )

#                 st.success("File successfully decrypted!")

#             except Exception as e:
#                 st.error("Decryption failed: " + str(e))


# ------------------------------------------------------------
# EVENT LOG PANEL — Persistent State (NO RESET)
# ------------------------------------------------------------
st.markdown("---")
st.header("📄 All Stored Files (Event Log with Persistent Decrypt)")

# Initialize session state
if "events_loaded" not in st.session_state:
    st.session_state.events_loaded = False

if "events" not in st.session_state:
    st.session_state.events = []

if "selected_event" not in st.session_state:
    st.session_state.selected_event = None

# BUTTON: Load events
if st.button("Load all stored files", key="load_events_btn"):
    evs = load_events()
    if not evs:
        st.info("No files stored yet")
    else:
        st.session_state.events = evs
        st.session_state.events_loaded = True
        st.success(f"Loaded {len(evs)} files from blockchain")

# If no events loaded yet → stop here
if not st.session_state.events_loaded:
    st.stop()

events = st.session_state.events

# Display table of events
st.table([
    {
        "filename": e["filename"],
        "fileHash": e["fileHash"],
        "cid": e["cid"],
        "owner": e["owner"],
        "timestamp": e["timestamp"]
    }
    for e in events
])

st.markdown("### 🔽 Select a file to decrypt")

# DROPDOWN (with session persistence)
selected_label = st.selectbox(
    "Choose a stored file:",
    options=[f"{e['filename']} | {e['fileHash'][:12]}..." for e in events],
    key="select_event_dropdown"
)

# Save selected event in session state
selected_event = events[
    [f"{e['filename']} | {e['fileHash'][:12]}..." for e in events].index(selected_label)
]
st.session_state.selected_event = selected_event

st.write("**Filename:**", selected_event["filename"])
st.write("**CID:**", selected_event["cid"])
st.write("**Hash:**", selected_event["fileHash"])
st.write("**Owner:**", selected_event["owner"])
st.write("**Timestamp:**", selected_event["timestamp"])

# DECRYPT BUTTON
if st.button("🔓 Decrypt Selected File", key="decrypt_selected_btn"):
    try:
        cid = selected_event["cid"]

        # Step 1 — download encrypted file from IPFS
        st.info("Downloading encrypted file from IPFS…")
        r = requests.get(f"https://ipfs.io/ipfs/{cid}")

        if r.status_code != 200:
            st.error("Download failed from IPFS gateway")
            st.stop()

        enc_blob = r.content
        st.success(f"Downloaded encrypted ({len(enc_blob)} bytes)")

        # Step 2 — compute hash
        file_hash = sha256_bytes(enc_blob)

        # Step 3 — fetch blockchain record
        rec = contract.functions.getFileWithKeyAndCID(file_hash).call()
        if rec[0] == "":
            st.error("Blockchain record not found – hash mismatch")
            st.stop()

        filename, _, _, _, encKeyB64, _ = rec

        # Step 4 — decrypt AES key
        aes_key = rsa_decrypt_key(base64.b64decode(encKeyB64), RSA_PRIVATE)

        # Step 5 — decrypt file
        plain = aes_decrypt_bytes(enc_blob, aes_key)

        # Step 6 — download decrypted file
        st.download_button(
            "⬇️ Download decrypted file",
            data=plain,
            file_name=f"decrypted_{filename}",
            key="download_file_btn"
        )

        st.success("Decryption complete!")

    except Exception as e:
        st.error("Decryption error: " + str(e))
