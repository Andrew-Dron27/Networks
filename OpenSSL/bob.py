#   This file runs one server to establish a connection another remote server(alice) using the OpenSSL handshake

import json
import socket
import sys
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding as pad
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# construct the digest containing bob's name, the public key, and the public key
# signed by the certificate agency to be sent to alice
def construct_digest(ca_priv_key, bob_pub):
    # sign bobs public key with the certificate private key
    try:
        signature = ca_priv_key.sign(bob_pub,
                                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                    hashes.SHA256())
    except:
        print("Failed to sign bobs public key")
        exit(1)
    # enocde the signature to alphanumerics
    sig = base64.b64encode(signature)

    digest = {
        "name": "bob",
        "pub_key": bob_pub.decode(),
        "signature": sig.decode()
    }

    digest_json = json.dumps(digest)
    return digest_json


# remove any padding added to the message sent by alice
def unpad_message(message):
    unpadder = pad.PKCS7(128).unpadder()
    return unpadder.update(message) + unpadder.finalize()


# set up a socket connection on the given port and localhost
def establish_connection(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', port);
    print('waiting for connection on  ' + str(server_address))
    sock.bind(server_address)
    sock.listen(50)
    connection, client_address = sock.accept()
    print('connection from' + str(client_address))
    return connection


# decrypts the given json library for a text message sent from alice
# use private key to decrypt the given symmetric key then uses the
# symmmetric key to decrypt the message and the message hash
# rehash the message and compare the hashes for message integrity
def verify_text(response, bob_priv_key):
    message = response["message"]
    verify = response["verify"]
    key = response["key"]

    # convert all the values to byte type
    key = key.encode()
    key = base64.b64decode(key)
    verify = base64.b64decode(verify)
    message = base64.b64decode(message)

    # collect bob's symmetric key and parse values from key
    try:
        sym_key = bob_priv_key.decrypt(key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                     algorithm=hashes.SHA256(), label=None))
    except:
        print("Failed to decrypt ")
        exit(1)
    sym_key = sym_key
    AES_key = sym_key[0:32]
    IV = sym_key[32:]

    cipher = Cipher(algorithms.AES(AES_key), modes.CBC(IV), backend=default_backend())

    # decrypt the message
    decryptor = cipher.decryptor()
    try:
        decrypt_message = decryptor.update(message) + decryptor.finalize()
    except:
        print("Failed to decrypt message")
        exit(1)

    # decrypt the hash
    decryptor = cipher.decryptor()
    decrypt_hash = decryptor.update(verify) + decryptor.finalize()

    # hash the decrypted message and compare that to the given message hash
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    try:
        hasher.update(decrypt_message)
        message_hash = hasher.finalize()
    except:
        print("unable to hash message")
        exit(1)

    # check the hash of the received message to verify message integrity
    if message_hash != decrypt_hash:
        print("ERROR: The SHA256 hash is incorrect for the received message\n")
        exit(1)

    print("MESSAGE VERIFIED!!\n")
    decrypt_message = unpad_message(decrypt_message)
    print(decrypt_message.decode())
    return;


def verify_file(response, bob_priv_key):
    file_name = response["file_name"]
    contents = response["contents"]
    verify = response["verify"]
    key = response["key"]

    #decode the files to byte type
    file_name = base64.b64decode(file_name)
    contents = base64.b64decode(contents)
    verify = base64.b64decode(verify)
    key = base64.b64decode(key)

    try:
        sym_key = bob_priv_key.decrypt(key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                         algorithm=hashes.SHA256(), label=None))
    except:
        print("unable to decrypt symmetric key")
        exit(1)
    AES_key = sym_key[0:32]
    IV = sym_key[32:]

    cipher = Cipher(algorithms.AES(AES_key), modes.CBC(IV), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        decrypt_file_name = decryptor.update(file_name) + decryptor.finalize()
    except:
        print("unable to decrypt file name")
        exit(1)

    decryptor = cipher.decryptor()
    try:
        decrypt_file_content = decryptor.update(contents) + decryptor.finalize()
    #reuse the decryptor to decrypt the file contents hash
    except:
        print("unable to ")
    decryptor = cipher.decryptor()
    decrypt_hash = decryptor.update(verify) + decryptor.finalize()

    #unpad the decrypted information


    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    try:
        hasher.update(decrypt_file_content)
        content_hash = hasher.finalize()
    except:
        print("Failed to encrypt file content")
        exit(1)
    decrypt_file_name = unpad_message(decrypt_file_name)
    decrypt_file_content = unpad_message(decrypt_file_content)
    if content_hash != decrypt_hash:
        print("ERROR Hash of file is different than received hash")
        exit(1)
    print("File contents verified")
    print("FILE NAME: " + decrypt_file_name.decode() + "\n")
    print("FILE CONTENT: " + decrypt_file_content.decode() + "\n")
    print("SAVING FILE TO FILE SYSTEM")
    try:
        with open(decrypt_file_name.decode(), 'w') as file:
            file.write(decrypt_file_content.decode())
    except:
        print("Failed to save file to file system")
        exit(1)



if __name__ == '__main__':
    # load data from given command line files
    for i in range(1, sys.argv.__len__()):
        if sys.argv[i] == "-port":
            port = int(sys.argv[i + 1])
    try:
        bob_pub = open(sys.argv[4], "rb").read()
        bob_priv = open(sys.argv[3], "rb")
        ca_priv = open(sys.argv[5], "rb")
    except:
        print("INCORRECT COMMAND LINE ARGUMENTS")

    try:
        bob_pub_key = load_pem_public_key(bob_pub, backend=default_backend())
        bob_priv_key = load_pem_private_key(bob_priv.read(), password=None, backend=default_backend())
        ca_priv_key = load_pem_private_key(ca_priv.read(), password=None, backend=default_backend())
    except:
        print("unable to parse RSA keys")
        exit(1)

    connection = establish_connection(port)

    print("Sending digest information: ")
    digest_json = construct_digest(ca_priv_key, bob_pub)
    print(digest_json)
    #wait for message greeting from alice
    data = connection.recv(1024)
    print("message from alice: " ,data.decode())
    connection.sendall(digest_json.encode())

    # get data from alice
    data = b""
    try:
        while True:
            datum = connection.recv(2048)
            if len(datum) == 0:
                break;
            data += datum
    except:
        print("Faild to read ")
        exit(1)


    response = json.loads(data)

    # check whether file or text
    if "file_name" in response:
        verify_file(response, bob_priv_key)
    else:
        verify_text(response, bob_priv_key)

    print("Message received, closing connection \n")
    connection.close()
