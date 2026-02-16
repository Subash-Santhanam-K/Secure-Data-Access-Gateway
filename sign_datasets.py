import os
import crypto_utils
from cryptography.fernet import Fernet

SECURE_DIR = "secure_data"

def sign_datasets():
    print("Signing existing datasets...")
    
    # Get Cipher to decrypt first
    cipher = crypto_utils.get_cipher()
    
    for filename in os.listdir(SECURE_DIR):
        if filename.endswith(".enc"):
            file_path = os.path.join(SECURE_DIR, filename)
            dataset_id = filename.split("_")[1].split(".")[0]
            sig_file_path = os.path.join(SECURE_DIR, f"dataset_{dataset_id}.sig")
            
            print(f"Processing {filename}...")
            
            # Read Encrypted Data
            with open(file_path, "rb") as f:
                encrypted_data = f.read()
                
            # Decrypt to get Plaintext
            try:
                plaintext = cipher.decrypt(encrypted_data)
            except Exception as e:
                print(f"Error decrypting {filename}: {e}")
                continue
                
            # Hash Plaintext
            hash_val = crypto_utils.hash_data(plaintext)
            
            # Sign Hash
            signature = crypto_utils.sign_hash(hash_val)
            
            # Save Signature
            with open(sig_file_path, "wb") as f:
                f.write(signature)
                
            print(f"Created signature for Dataset {dataset_id}")

    print("All datasets signed.")

if __name__ == "__main__":
    sign_datasets()
