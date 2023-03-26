# create a conversation between two people
message_data = {
    #first person
    "Alex": [
        {"message": "Hey Okabo,how is it going", "time" "2023-03-21 10:30:00"},
        {"message": "not too bad,just working on some coding projects.Did you hear about the new encryption algorithim?", "time" "2023-03-21 10:35:00"},
        {"message": "Hey Divyansha,how is it going", "time" "2023-03-21 10:00"},

],


    #second person
"Okabo":[
    {"message": "Good, thanks! How about you?", "time" "2023-03-21 10:32:00"},
    {"message": "No! what is that", "time" "2023-03-21 10:37:00"},
    {"message": "Sure, lets do it", "time" "2023-03-21 10:30:00"},
]


# I import the module and generate the shared secret key for encryption and decription
    import os
    from cryptography.hazmat.primitives.ciphers import, algorithms,modes
    from cryptography.hazmat.backends import
    shared_secret_key = os.urandom(32)


# i define a function to keep the secret message save from other people who shold not see it
def encrypt_message(message, key):
    iv = 0s.urandom(16)
    cipher = Cipher(algorithms.AES(key),modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_message = message + (16 - len(message) %16)
    ciphertext = encryptor.update(*padded_message.encode()) + encryptor.finalize()
    return  iv + ciphertext


# i define a function to decrypt the message made using a key  and encryption
def decrypt_message(ciphertext, key):
    iv = ciphertext[: 16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = Cipher.decryptor()
    plaintext = decryptor.update(ciphertext[16:])
    padding_length = plaintext[-1]
    plaintext = plaintext[:-padding_length]
    return plaintext.decode()

#encrypt the dictionary with the encrypted message
for person, message in message_data.items():
    for message in messages:
        encrypt_message = encrypt_message(message["message"], shared_secret_key)
        message["message"] = encrypt_message.hex()

        print("encrypted message_data dictionary:")
        print("message_data"


#I decrypt the encrypted messages so that person having the key can see the message
for person, message in message_data.items():
    for message in messages:
        ciphertext = bytes.fromhex(message["message"])
        decrypt_message = decrypt_message(ciphertext, shared_secret_key)
        message["message"] = decrypted_message

        print("decrypted message_data dictionary:")
        print("message_data")

