# reference: https://github.com/beemdevelopment/Aegis/blob/master/app/src/main/java/com/beemdevelopment/aegis/importers/TwoFASImporter.java

import json
import base64
from pprint import pprint
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2



KEY_SIZE = 32
TAG_SIZE = 16
ITERATION_COUNT = 10_000
CRYPTO_AEAD_TAG_SIZE = 16



def backupRead(path: str):
    with open(file=path, mode="r", encoding="utf-8") as fp:
        return map(base64.b64decode, json.load(fp)["servicesEncrypted"].split(":"))
    
    

def deriveKey(password: str, salt: bytes):
    return PBKDF2(
        password = password,
        salt = salt,
        dkLen = KEY_SIZE,
        count = ITERATION_COUNT,
        hmac_hash_module = SHA256
    )



def backupDecrypt(password: str, data: bytes, salt: bytes, nonce: bytes):
    key = deriveKey(password, salt)
    cipher = AES.new(key=key, nonce=nonce, mode=AES.MODE_GCM)
    return json.loads(cipher.decrypt(data)[:-CRYPTO_AEAD_TAG_SIZE])



db = backupRead("./2fas-backup-XXXXXXXXXXXXX.2fas")
pprint(backupDecrypt("somepass", *db))