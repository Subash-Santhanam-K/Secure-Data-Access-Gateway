import os
import crypto_utils

def migrate():
    print("Starting Migration to Hybrid Encryption...")
    
    # 1. Generate RSA Keys if not present
    if not os.path.exists(crypto_utils.PRIVATE_KEY_FILE) or not os.path.exists(crypto_utils.PUBLIC_KEY_FILE):
        print("Generating RSA Key Pair...")
        crypto_utils.generate_rsa_keys()
        print(f"RSA Keys generated in {crypto_utils.KEYS_DIR}/")
    else:
        print("RSA Keys already exist.")
        
    # 2. Check for Plaintext AES Key
    if os.path.exists(crypto_utils.KEY_FILE):
        print(f"Found plaintext AES key: {crypto_utils.KEY_FILE}")
        
        # Read plaintext key
        with open(crypto_utils.KEY_FILE, "rb") as f:
            aes_key = f.read()
            
        # Encrypt with RSA Public Key
        print("Encrypting AES key with RSA Public Key...")
        encrypted_aes_key = crypto_utils.encrypt_aes_key(aes_key)
        
        # Save Encrypted Key
        with open(crypto_utils.ENCRYPTED_KEY_FILE, "wb") as f:
            f.write(encrypted_aes_key)
        print(f"Saved encrypted AES key to {crypto_utils.ENCRYPTED_KEY_FILE}")
        
        # Delete Plaintext Key
        os.remove(crypto_utils.KEY_FILE)
        print("Deleted plaintext AES key.")
        
    elif os.path.exists(crypto_utils.ENCRYPTED_KEY_FILE):
        print("AES key is already encrypted. No migration needed.")
        
    else:
        print("No AES key found to migrate!")

    print("Migration Complete.")

if __name__ == "__main__":
    migrate()
