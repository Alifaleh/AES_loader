import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def enc(data,password):
    password=password.encode('utf-8')
    if str(type(data))!="<class 'bytes'>":
        data=data.encode('utf-8')
    salt = "\\xa4\\x84s=\\x01\\xaaf\\xf0\\x0b\\xb3\\x05\\xe33\\xa4mk".encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    k = kdf.derive(password)
    key = base64.urlsafe_b64encode(k)
    f = Fernet(key)
    token = f.encrypt(data)
    return token

def dec(token,password):
    password=password.encode('utf-8')
    if str(type(token)) != "<class 'bytes'>":
        token = token.encode('utf-8')
    salt = "\\xa4\\x84s=\\x01\\xaaf\\xf0\\x0b\\xb3\\x05\\xe33\\xa4mk".encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    k = kdf.derive(password)
    key = base64.urlsafe_b64encode(k)
    f = Fernet(key)
    data = f.decrypt(token)
    return data

def enc_file(file_name,password):
    file = open(file_name, "rb")
    data = file.read()
    file.close()
    b_data=base64.b64encode(data)
    token = enc(b_data+file_name[-3:].encode('utf-8'),password)
    file = open(file_name[:-3] + 'ali', "wb")
    file.write(token)
    file.close()
    print(file_name+" was encrypted successfully.")
    os.remove(file_name)

def dec_file(file_name,password):
    file = open(file_name, "rb")
    token = file.read()
    file.close()
    data=dec(token,password)
    extention = str(data)[-4:-1]
    data = base64.b64decode(str(data)[2:-4])
    file = open(file_name[:-3] + extention, "wb")
    file.write(data)
    file.close()
    print(file_name+" was decrypted successfully.")
    os.remove(file_name)

def load_file(file_name,password):
    file = open(file_name, "rb")
    data = file.read()
    file.close()
    b_data=base64.b64encode(data)
    token = enc(b_data+file_name[-3:].encode('utf-8'),password)
    return token

def extract_file (token,password,file_name,to="",hiden=False):
    if to!="":
        to=to+"\\"
    data=dec(token,password)
    extention=""
    if data[0]=="b":
        extention = str(data)[-4:-1]
        data = base64.b64decode(str(data)[2:-4])
    else:
        extention = str(data)[-3:]
        data = base64.b64decode(str(data)[:-3])
    file = open(to+file_name+"." + extention, "wb")
    file.write(data)
    file.close()
    if hiden:
        os.system("attrib +h " + to+file_name+"." + extention)


def inject_file(src,dst,flag,password):
    src_file=load_file(src,password)
    if src_file[0]!="b":
        src_file="b'"+src_file+"'"
    file=open(dst,"r")
    code=file.read()
    file.close()
    code=code.replace(flag,str(src_file))
    file=open(dst[:-3]+"_AES_loaded.py","w")
    file.write(code)
    file.close()
