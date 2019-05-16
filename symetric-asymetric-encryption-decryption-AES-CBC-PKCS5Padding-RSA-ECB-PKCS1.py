'''
https://daniellimws.github.io/rsa-java-to-python.html

***create certificate***
req -x509 -newkey rsa:4096 -sha256 -keyout example.key -out example.crt

***get public key from certificate***
openssl rsa  -pubout -in example.key

***open ssl private key to rsa private key***
openssl rsa -in example.key -out ssl.key.decrypted
'''
import rsa
import base64
import uuid
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES,PKCS1_v1_5
from Crypto import Random
public_key_server = '''-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA+xGZ/wcz9ugFpP07Nspo6U17l0YhFiFpxxU4pTk3Lifz9R3zsIsu
ERwta7+fWIfxOo208ett/jhskiVodSEt3QBGh4XBipyWopKwZ93HHaDVZAALi/2A
+xTBtWdEo7XGUujKDvC2/aZKukfjpOiUI8AhLAfjmlcD/UZ1QPh0mHsglRNCmpCw
mwSXA9VNmhz+PiB+Dml4WWnKW/VHo2ujTXxq7+efMU4H2fny3Se3KYOsFPFGZ1TN
QSYlFuShWrHPtiLmUdPoP6CV2mML1tk+l7DIIqXrQhLUKDACeM5roMx0kLhUWB8P
+0uj1CNlNN4JRZlC7xFfqiMbFRU9Z4N6YwIDAQAB
-----END RSA PUBLIC KEY-----'''

private_key_client = '''-----BEGIN RSA PRIVATE KEY-----
MIIBCgKCAQEA+xGZ/wcz9ugFpP07Nspo6U17l0YhFiFpxxU4pTk3Lifz9R3zsIsu
ERwta7+fWIfxOo208ett/jhskiVodSEt3QBGh4XBipyWopKwZ93HHaDVZAALi/2A
+xTBtWdEo7XGUujKDvC2/aZKukfjpOiUI8AhLAfjmlcD/UZ1QPh0mHsglRNCmpCw
mwSXA9VNmhz+PiB+Dml4WWnKW/VHo2ujTXxq7+efMU4H2fny3Se3KYOsFPFGZ1TN
QSYlFuShWrHPtiLmUdPoP6CV2mML1tk+l7DIIqXrQhLUKDACeM5roMx0kLhUWB8P
+0uj1CNlNN4JRZlC7xFfqiMbFRU9Z4N6YwIDAQAB
-----END RSA PRIVATE KEY-----'''
block_size = AES.block_size

class EncryptionDecryption:

    def __init__(self):
        self.block_size = AES.block_size
        self.iv = self.get_iv()
        self.session_key = self.get_session_key()

    def get_session_key(self):
        uid = uuid.uuid4()
        return uid.hex[:16]

    def get_iv(self):
        '''
        16 alphanumeric character
        '''
        uid = uuid.uuid4()
        return uid.hex[:16]

    def pad(self, plain_text):
        number_of_bytes_to_pad = self.block_size - len(plain_text) % self.block_size
        ascii_string = chr(number_of_bytes_to_pad)
        padding_str = number_of_bytes_to_pad * ascii_string
        padded_plain_text =  plain_text + padding_str
        return padded_plain_text

    def unpad(self, plan_text):
        return plan_text[:-ord(plan_text[len(plan_text)-1:])]

    def encrypt_key(self, public_key_server):
        '''
        Create Session key with assymentic encryption
        '''
        PUBLIC_KEY_SERVER = RSA.importKey(base64.b64decode(public_key_server))
        session_key = self.session_key.encode('utf8')
        return base64.b64encode(rsa.encrypt(session_key, PUBLIC_KEY_SERVER))

    def decrypt_key(self, encrypted_key_data, private_key_client):
        '''
        Return Server Session Key, decrypt with assymetric decryption
        '''
        PRIVATE_KEY_CLIENT = RSA.importKey(base64.b64decode(private_key_client))
        cipher = PKCS1_v1_5.new(PRIVATE_KEY_CLIENT)
        return cipher.decrypt(encrypted_key_data, "Error while decrypting")

    def encrypt_data(self, data):
        '''
        Encrypt data with key
        '''
        cipher = AES.new(self.session_key, AES.MODE_CBC, self.iv )
        return base64.b64encode(cipher.encrypt(self.pad(self.iv+data)))

    def decrypt_data(self, key, data):
        enc = base64.b64decode(data)
        iv = enc[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return self.unpad(cipher.decrypt(enc[16:])).decode('utf-8')

    def make_request(self, url, method, data, headers, public_key_server=None, private_key_client=None, encryption=True):

        if encryption:
            payload = {
                        "encryptedKey": self.encrypt_key(public_key_server),
                        "iv":self.iv,
                        "encryptedData":self.encrypt_data(data).decode('utf8'),
                    }
            response = requests.request(method, url, json=payload, headers=headers)

            data = response.json()
            decrypt_key = self.decrypt_key(base64.b64decode(data.get('encryptedKey')), private_key_client)
            decrypt_data = self.decrypt_data(decrypt_key.decode(), data['encryptedData'])
            return decrypt_data
        else:
            response = requests.request(method, url, data=payload, headers=headers)
            return response
