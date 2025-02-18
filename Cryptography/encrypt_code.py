import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass

def generate_key(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_code(source_file, password):
    with open(source_file, 'r') as f:
        source_code = f.read()
    
    key, salt = generate_key(password)
    fernet = Fernet(key)
    
    encrypted_code = fernet.encrypt(source_code.encode())
    
    encrypted_file = source_file.replace('.py', '_encrypted.py')
    
    loader_code = f'''
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass

def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def decrypt_and_run():
    SALT = {salt}
    ENCRYPTED_CODE = {encrypted_code}
    
    password = getpass.getpass("Enter password to decrypt and run the code: ")
    
    try:
        key = generate_key(password, SALT)
        fernet = Fernet(key)
        decrypted_code = fernet.decrypt(ENCRYPTED_CODE).decode()
        exec(decrypted_code)
    except Exception as e:
        print("Error: Invalid password or corrupted code")
        exit(1)

if __name__ == "__main__":
    decrypt_and_run()
'''
    
    with open(encrypted_file, 'w') as f:
        f.write(loader_code)
    
    print(f"Code encrypted and saved to {encrypted_file}")
    print("Original source file should now be deleted for security")

if __name__ == "__main__":
    source_file = input("Enter the path to your source code file: ")
    password = getpass.getpass("Enter password for encryption: ")
    confirm_password = getpass.getpass("Confirm password: ")
    
    if password != confirm_password:
        print("Passwords do not match!")
        exit(1)
    
    encrypt_code(source_file, password)