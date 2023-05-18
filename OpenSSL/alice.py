
#   This file runs one server to establish a connection another remote server(bob) using the OpenSSL handshake

import sys
import socket
import json
import os
import base64
from cryptography.hazmat.primitives import hashes, padding as pad
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# set up socket connection on local-host and given port
def establish_connection(port, ip_address):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if ip_address == "10.0.0.10":
        ip_address = 'localhost'
    server_address = (ip_address, port)
    print('waiting for connection on  ' + str(server_address))
    sock.connect(server_address)
    return sock


# pads the given message to be a length of the closest multiple of 16 bytes
def pad_message(message):
    padder = pad.PKCS7(128).padder()
    pad_data = padder.update(message.encode()) + padder.finalize()
    return pad_data


# create a json library of the encrypted message, hash and public key for bob
def construct_json_text(sym_key, message, bob_pub):
    cipher = Cipher(algorithms.AES(sym_key[0]), modes.CBC(sym_key[1]), backend=default_backend())
    encryptor = cipher.encryptor()
    message = pad_message(message)

    try:
        message_encrypt = encryptor.update(message) + encryptor.finalize()
    except:
        print("failed to encrypt message")
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(message)

    # reuse the encryptor
    encryptor = cipher.encryptor()
    try:
        bob_pub_key = load_pem_public_key(bob_pub.encode(), backend=default_backend())
    except:
        print("failed to load bobs public key")


    AES_key = bytes(sym_key[0]) + bytes(sym_key[1])
    try:
        key = bob_pub_key.encrypt(AES_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                    algorithm=hashes.SHA256(), label=None))
    except:
        print("unable to encrypt symmetric key")
    # construct the json object with the parameters converted to strings
    message_dict = {
        "message": base64.b64encode(message_encrypt).decode(),
        "verify": base64.b64encode(encryptor.update(hasher.finalize()) + encryptor.finalize()).decode(),
        "key": base64.b64encode(key).decode()
    }
    json_message = json.dumps(message_dict)

    return json_message


# construct json dictionary of the encrypted filename, contents, hash of file contents
# and public key for bob
def construct_json_file(sym_key, file_name, bob_pub):

    file_contents = open(file_name).read()

    #pad file-name and content for encryption
    file_name = pad_message(file_name)
    file_contents = pad_message(file_contents)

    cipher = Cipher(algorithms.AES(sym_key[0]), modes.CBC(sym_key[1]), backend=default_backend())
    encryptor = cipher.encryptor()
    try:
        file_name_encrypt = encryptor.update(file_name) + encryptor.finalize()
    except:
        print("Failed to file name")
        exit(1)
    # reuse the encryptor for the file contents
    encryptor = cipher.encryptor()
    try:
        file_contents_encrypt = encryptor.update(file_contents) + encryptor.finalize()
    except:
        print("Failed to encrypt file contents")
        exit(1)
    encryptor = cipher.encryptor()
    # hash the file contents
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(file_contents)

    bob_pub_key = load_pem_public_key(bob_pub.encode(), default_backend())
    #concat the AES-key and IV together
    AES_key = bytes(sym_key[0]) + bytes(sym_key[1])
    try:
        key = bob_pub_key.encrypt(AES_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                        algorithm=hashes.SHA256(), label=None))
    except:
        print("Unable to encrypt the symmetric key")
    message_dict = {
        "file_name": base64.b64encode(file_name_encrypt).decode(),
        "contents": base64.b64encode(file_contents_encrypt).decode(),
        "verify": base64.b64encode(encryptor.update(hasher.finalize()) + encryptor.finalize()).decode(),
        "key": base64.b64encode(key).decode()
    }

    json_message = json.dumps(message_dict)

    return json_message


if __name__ == '__main__':
    # parse command line
    message = None
    file_name = None
    for i in range(1, sys.argv.__len__()):
    #   if sys.argv[i] == "10.0.0.10":
    #        ip = sys.argv[i]
        if sys.argv[i] == "-port":
            port = int(sys.argv[i + 1])
    #    elif sys.argv[i] == "certificate_agency_public.pem":
    #        ca_pub = open(sys.argv[i], "rb")
        if sys.argv[i] == "-message":
            message = sys.argv[i + 1]
        if sys.argv[i] == "-file":
            file_name = sys.argv[i + 1]
    ip = sys.argv[1]
    port = int(sys.argv[3])
    ca_pub = open(sys.argv[4],"rb")

    # load certificate public key
    try:
        ca_pub_key = load_pem_public_key(ca_pub.read(), backend=default_backend())
    except:
        print("faile to load bobs public key")

    connection = establish_connection(port, ip)
    connection.sendall(b"Hello")
    # receive digest from bob
    data = connection.recv(4096)
    digest = json.loads(data)

    # verify that we are indeed talking to bob
    if digest["name"] != "bob":
        print("ERROR: Could not parse bobs name ")
        exit(1)

    bob_pub = digest["pub_key"]
    signature = digest["signature"]

    # decode signature to byte type
    sig = base64.b64decode(signature)
    try:
        ca_pub_key.verify(sig, bob_pub.encode(),
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
                            ,hashes.SHA256())
    except:
        print("Failed to verify bobs public key")
        exit(0)
    # generate symmetric key to encrypt message
    key = os.urandom(32)
    iv = os.urandom(16)

    sym_key = (key, iv)

    # handle file or a message
    if message:
        json_message = construct_json_text(sym_key, message, bob_pub)

    elif file_name:
        json_message = construct_json_file(sym_key, file_name, bob_pub)
    else:
        print("ERROR: please supply a file name/ text message to send")
        exit(1)

    # send message to bob
    #print("Sending message to bob: " + json_message["message"])
    connection.send(json_message.encode())

    print("message sent successfully, closing connection \n")
    connection.close()
