
import os
import platform
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

# MUST USE PYTHON 3.5
# Python 3.6 doesn't seem to work right now
class MD5:

    def __init__(self, hxstr, btstr):
        self.HexString = hxstr
        self.ByteString = btstr


class Encryption(object):
    """
    This class does the heavy lifting of encrypting string, decrypting strings, generating
    RSA Key-pair, or pulling the MD5 hash of a file. There is a default secret_code,
    but shouldn't have to tell you ... never use the default outside of development.
    """

    def __init__(self):
        self.__encrypted_message = None
        self.__decrypted_message = None

    def encrypt(self, privateData, publickey_file, output_file=None):

        if type(privateData) is str:
            privateData = privateData.encode("utf-8")

        pubkey = RSA.import_key(open(publickey_file, 'r').read())
        cipher_rsa = PKCS1_OAEP.new(pubkey)
        encrypted_message = cipher_rsa.encrypt(privateData)

        self.__decrypted_message = None
        self.__encrypted_message = base64.b64encode(encrypted_message)
        if output_file:
            with open(output_file, 'wb') as f:
                f.write(self.__encrypted_message)
                f.close

    def get_encrypted_message(self):
        return self.__encrypted_message

    def decrypt(self, private_key_file, encrypted_data, secret_code=None):

        if os.path.isfile(encrypted_data):
            with open(encrypted_data, 'rb') as f:
                encrypted_data = f.read()
                f.close()
        if isinstance(secret_code, str):
            # encode this to a bytes object
            secret_code = secret_code.encode('utf-8')

        if secret_code:
            private_key = RSA.import_key(open(private_key_file, 'rb').read(), passphrase=secret_code)
        else:
            private_key = RSA.import_key(open(private_key_file, 'rb').read())

        encrypted_data = base64.b64decode(encrypted_data)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        privateData = cipher_rsa.decrypt(encrypted_data)

        self.__decrypted_message = str(privateData, "utf-8")
        self.__encrypted_message = None

    def get_decrypted_message(self):
        return self.__decrypted_message

    def generate_rsa_key_pair(self, public_file=None, private_file=None,
                              secret_code=b'N-6NZG\xff<\xddL\x85:\xc5\xc4\xa8n'):

        key = RSA.generate(4096)

        private, public = key.exportKey(passphrase=secret_code, pkcs=8,
                                        protection="scryptAndAES256-CBC"), key.publickey().exportKey()

        with open(private_file, 'wb') as f:
            f.write(private)
            f.close
        with open(public_file, 'wb') as f:
            f.write(public)
            f.close

        setattr(self, 'PublicKey_file', public_file)
        setattr(self, 'PrivateKey_file', private_file)

        return self

    def get_rsa_public_key_from_private_key(self, file_path=None, encrypted_key=None,
                                            secret_code=b'N-6NZG\xff<\xddL\x85:\xc5\xc4\xa8n'):

        if file_path:
            encrypted_key = open(file_path, 'rb').read()

        key = RSA.import_key(encrypted_key, passphrase=secret_code)

        setattr(self, 'PublicKey', key.publickey().exportKey())

        return self

    def md5(self, fname):
        import hashlib

        hash_md5 = hashlib.md5()

        with open(fname, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
            f.close()
        setattr(self, 'md5_info', MD5(hash_md5.hexdigest(), hash_md5.digest()))
        return self.md5_info
