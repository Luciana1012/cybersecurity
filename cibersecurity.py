"""
Author: Luciana C.
Last modified: 5/5/2021
Intech IT - Cybersecurity 2021
"""

def ceaserEncrypt(plaintext):
    """Encrypt the plaintext with Caesar Cipher algorithm.
        Parameters:
            plainText (str) : plaintext to be encrypted
        Returns:
            result (str): encrypted cipher text
    """ 
    result = ""
    for i in range (0, len(plaintext)):
        character = plaintext[i]
        result += chr((ord(character) + 5 - 97) % 26 + 97) #26 characters in the alphabet and 97 is A in ASCII convert each character of plaintext into ascii and shift by 3 forward
    return result

#print (ceaserEncrypt("well done everyone"))

#Encryption and Decryption only works with lower case characters:
def ceaserDecrypt(ciphertext):
    """Decrypt the ciphertext with Caesar Cipher algorithm.
    Parameters:
        plainText (str): cipherText to be decrypted
    Returns:
        result (str) : decrypted plainText

    """ 
    result = ""
    for i in range (0, len(ciphertext)):
        character = ciphertext[i]
        result += chr((ord(character) - 5
         - 97) % 26 + 97)
    return result

#print (ceaserEncrypt("this is a test"))
#print (ceaserDecrypt("bjqqsitsjsjajwdtsj"))
############# Activity 2 Symmetric algorithms ###########
import cryptography # install and import the cryptography library - pip install cryptography
from cryptography.fernet import Fernet

def generate_symmetric_key():
    """Generate a key to use for encryption/decryption"""

    key =Fernet.generate_key()
    f = open("secretKey", "wb")
    f.write(key)
    f.close()
    print(key)

def symmetric_encrypt (plainText):
    """Encrypt the plaintText with symmetric encryption algorithm.
        Parameters:
            plainText (str): plainText to be encrypted.
    """

    f = open("secretKey", "rb")
    key = f.read()
    f.close()
    key = Fernet(key)
    cipherText = key.encrypt(plainText.encode())
    f = open("symmetricCipherText", "wb")
    f.write(cipherText)
    f.close()
    print(cipherText)

def symetric_decrypt():
    """Decrypt the cipherText with symmetric decryption algorithm. """
    
    f = open("secretKey", "rb")
    key = f.read()
    f.close()
    key = Fernet(key)

    f = open("symmetricCipherText", "rb")
    cipherText = f.read()
    f.close()
    plainText = key.decrypt(cipherText)
    print(plainText)

##generate_symetric_key()
##symmetric_encrypt("This is a test")
#symetric_decrypt()

from cryptography.hazmat.backends import default_backend # importing more modules from the same cryptography library
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


#def encrypt():

#def decrypt():

def generate_asymmetric_key():
    """ Generate a private and public key to be used for encryption/decryption. Save both keys to file"""
    
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    pem = private_key.private_bytes(encoding = serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())

    with open('private_key.pem', 'wb') as f:
        f.write(pem)


    pem = public_key.public_bytes(encoding = serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    with open('public_key.pem', 'wb') as f:
	    f.write(pem)

def asymmetric_encrypt(plainText):
    """Perform encryption of the plainText using asymmetric encryption (using public key to encrypt).

    Parameters:
        plainText (str): plaintext to encrypt
    
    """
    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

    cipherText = public_key.encrypt(plainText, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    
    with open("asymmetricCipherText", "wb") as f:
        f.write(cipherText)

    print(cipherText)

def asymmetric_decrypt():
    """ Perform decryption of the cipherText using asymetric decryption (using private key to decrypt)"""
    with open("private_key.pem", "rb")as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    with open("asymmetricCipherText", "rb") as f:
            cipherText = f.read()

    plainText = private_key.decrypt(cipherText, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

    print(plainText)


##generate_asymmetric_key()
##asymmetric_encrypt(b"this is a test")

asymmetric_decrypt()
