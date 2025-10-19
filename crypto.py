import nodes
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

class InvalidKeyError(Exception):
    def __init__(self,msg="Key size must be exactly 16 bytes"):
        self.msg=msg
        super().__init__(self.msg)

def encrypt_data(data,key,nonce=None): #key size must be 16 bytes/ 16 chars
    try:
        cipher=AES.new(key, AES.MODE_EAX)
        if nonce==None:
            nonce=cipher.nonce
        ciphertext, tag=cipher.encrypt_and_digest(data)
        return ciphertext, tag, nonce
    except ValueError as e:
        print(f"Error: {e}")

def decrypt_data(ciphertext,key,tag,nonce):
    try:
        cipher=AES.new(key, AES.MODE_EAX, nonce=nonce)
        plaintext=cipher.decrypt(ciphertext)
        cipher.verify(tag)
        return plaintext
    except ValueError as e:
        print(f"Error: {e}")


def generate_pub_pri_keys(prifile="myprivatekey.pem",pubfile="mypublickey.pem",pwd = b'cipher_of_secrets'):
    prikey= RSA.generate(3072)
    pubkey=prikey.publickey()
    with open(prifile, "wb") as f:
        data = prikey.export_key(passphrase=pwd,pkcs=8,protection='PBKDF2WithHMAC-SHA512AndAES256-CBC',prot_params={'iteration_count':131072})
        f.write(data)
    with open(pubfile,"wb") as f:
        data=pubkey.export_key()
        f.write(data)

def get_pub_key(file="mypublickey.pem",pwd= b'cipher_of_secrets'):
    with open(file,"rb") as f:
        pub=f.read()
        pubkey=RSA.import_key(pub,pwd)
        return pubkey

def get_pri_key(file="myprivatekey.pem",pwd= b'cipher_of_secrets'):
    with open(file, "rb") as f:
        pri = f.read()
        prikey = RSA.import_key(pri,pwd)
        return prikey

def pubkey_encrypt(plaintext,public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key ,hashAlgo=SHA256)
    ciphertext = cipher_rsa.encrypt(plaintext)
    return ciphertext

def prikey_decrypt(ciphertext,private_key):
    try:
        cipher_rsa = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        plaintext = cipher_rsa.decrypt(ciphertext)
        return plaintext
    except ValueError as e:
        print(f"{e} (Data mismatch or data corrupted)")

def main():
    a=nodes.Node('33xxv4','10.20.30')
    b=nodes.Node('44yy55','200.30.01')
    a.set_data("this is my secret message")
    key=b"this_is_my_key.."
    ciphertext,tag,nonce=encrypt_data(a.data.encode(),key)
    plaintext=decrypt_data(ciphertext,key,tag,nonce)
    print(ciphertext,plaintext,sep='\n')

if __name__=="__main__":
    main()