<div align="center">

# 🔐 Encrypted File Vault  
### **AES + RSA + IPFS + Ethereum Blockchain + Streamlit UI**

A fully decentralized & secure file storage system combining **AES encryption**, **RSA key wrapping**, **IPFS for file storage**, and **Ethereum smart contracts for metadata** — wrapped in a modern **Streamlit Web App**.

---

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-App-red)
![IPFS](https://img.shields.io/badge/IPFS-Decentralized-blueviolet)
![Ethereum](https://img.shields.io/badge/Ethereum-Smart--Contract-6C23F8)
![Security](https://img.shields.io/badge/Security-AES--256%20%7C%20RSA--2048-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

</div>

---

## 📘 Overview

This project implements a **fully decentralized encrypted file vault**, enabling secure file upload, storage, and retrieval using:

- **AES-256 encryption** for file content  
- **RSA-2048 OAEP** for encrypting the AES key  
- **IPFS** for decentralized storage of encrypted files  
- **Ethereum Blockchain (Ganache)** for storing metadata  
- **Streamlit UI** for user-friendly interaction  

---

## 🏗️ System Architecture

```txt
User (Streamlit UI)
        │
        ▼
AES Encrypt File → RSA Encrypt AES Key
        │
        ▼
Upload Encrypted File → IPFS
        │
        ▼
Store metadata on Ethereum:
  • filename
  • SHA256 hash
  • IPFS CID
  • RSA-encrypted AES key
        │
        ▼
Retrieve (CID) → Recompute Hash → Blockchain Lookup
        │
        ▼
RSA Decrypt AES Key → AES Decrypt File → Download
```

---

## ✨ Features

### 🔒 Encryption
- AES-256 CBC file encryption  
- RSA-2048 key encryption  

### 🧊 Decentralized Storage
- Encrypted files stored on IPFS  
- Metadata stored on blockchain  
- Tamper-proof and censorship-resistant  

### 🖥️ Modern Streamlit UI
- Sidebar navigation  
- Upload → Encrypt → IPFS → Blockchain  
- View all encrypted files  
- One-click decrypt & download  
- Clean dark-themed UI  

### 🧩 CID-Based Retrieval
- Retrieve files using IPFS CID  
- Hash auto-computed for blockchain lookup  
- Fully automated decryption flow  

---

## 📂 Project Structure

```txt
EncryptedVault/
│
├── crypto_utils/
│   ├── streamlit_app.py
│   ├── ipfs_uploader.py
│   ├── aes_encryption.py
│   ├── aes_hybrid_blockchain_multithread.py
│   ├── public.pem
│   └── private.pem
│
├── blockchain/
│   └── FileVaultWithIPFS.sol
│
└── test_files/
```

---

## 📦 Requirements

Create a `requirements.txt`:

```txt
streamlit==1.32.0
web3==6.11.4
requests==2.31.0
pycryptodome==3.20.0
pathlib==1.0.1
```

Install using:

```bash
pip install -r requirements.txt
```

---

## 🛠️ Setup Guide

### 1️⃣ Clone the Repository

```bash
git clone <your_repo_url>
cd EncryptedVault
```

### 2️⃣ Create Virtual Environment

```bash
python -m venv encry
encry\Scripts\activate      # Windows
source encry/bin/activate   # Linux/Mac
```

### 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

### 4️⃣ Start Ganache

Ensure RPC:
```
http://127.0.0.1:7545
```

### 5️⃣ Deploy Smart Contract

Deploy `FileVaultWithIPFS.sol` using Remix, copy contract address into:

```python
CONTRACT_ADDRESS = "0xYourContractAddressHere"
```

### 6️⃣ Generate RSA Keys

```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout > public.pem
```

### 7️⃣ Configure IPFS (Pinata)

Update `ipfs_uploader.py`:

```python
PINATA_API_KEY = "your_api_key"
PINATA_SECRET_API_KEY = "your_secret_key"
```

---

## 🚀 Run the Application

```bash
streamlit run crypto_utils/streamlit_app.py
```

Then open:

```
http://localhost:8501
```

---

## 🧪 Usage

### ▶ Upload & Encrypt File
- Select file  
- AES encrypt  
- RSA wrap AES key  
- Upload encrypted file to IPFS  
- Store metadata on blockchain  

### ▶ View All Stored Files
- Load blockchain events  
- View all encrypted files & CIDs  

### ▶ Decrypt & Download
- Select file  
- App retrieves CID  
- Computes correct SHA256  
- Fetches blockchain record  
- Decrypts and downloads file  

---

## 🛡 Security Model

| Component      | Implementation              |
|----------------|------------------------------|
| File Encryption | AES-256-CBC                 |
| Key Encryption  | RSA-2048 OAEP              |
| Integrity Check | SHA256                     |
| Storage         | IPFS (Pinata)              |
| Metadata        | Ethereum Blockchain         |
| UI              | Streamlit                   |

---

## 🌟 Future Enhancements

- Multi-user RSA sharing  
- Preview thumbnails for images/videos  
- Local IPFS node integration  
- Folder batch encryption  
- User authentication / password-protected keys  

---

## 📜 License

MIT License

---

## 👨‍💻 Author

Developed using:
- Python  
- Streamlit  
- Solidity  
- Web3.py  
- IPFS  
- AES/RSA cryptography  


