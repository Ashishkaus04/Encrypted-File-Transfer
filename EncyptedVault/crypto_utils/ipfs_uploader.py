# ipfs_uploader.py
import requests
import os

PINATA_API_KEY = "0b75d2d2eadb158ac8e3"
PINATA_SECRET_API_KEY = "9f44f163866d526a65fde252f94aa241cbbc68d693570db9bd340b8f17bd1542"

def upload_to_ipfs(filepath: str) -> str:
    url = "https://api.pinata.cloud/pinning/pinFileToIPFS"

    # Send only the filename, NOT the full Windows path
    safe_filename = os.path.basename(filepath)

    with open(filepath, "rb") as f:
        files = {
            'file': (safe_filename, f)   # <-- SAFE FILE NAME HERE
        }

        headers = {
            "pinata_api_key": PINATA_API_KEY,
            "pinata_secret_api_key": PINATA_SECRET_API_KEY
        }

        response = requests.post(url, files=files, headers=headers)

    # If upload fails, print error
    if response.status_code != 200:
        raise Exception(f"IPFS upload failed: {response.text}")

    data = response.json()
    cid = data["IpfsHash"]

    print(f"[✓] Uploaded to IPFS | CID = {cid}")
    return cid
