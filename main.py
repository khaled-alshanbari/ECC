import base64
import os
from time import sleep
from tkinter import filedialog
import hashlib
from tinyec import registry
import secrets
from ecies.utils import generate_eth_key
from ecies import encrypt, decrypt
import binascii
# get the Desktop path
def get_Desktop():
    desktop = os.path.join(os.path.join(os.path.expanduser('~')), 'Desktop')
    return desktop

class EC:
    def __init__(self): # initiating the object
        print("Generating Private and Public Keys....")
        self.privKey = generate_eth_key() # generate the private key
        self.PrivateKey = self.privKey.to_hex() # converting private ket to hexadecimal
        self.PublicKey = self.privKey.public_key.to_hex() # generating public key for private key and convert it to hexadecimal
        print('Private Key: ', self.PrivateKey)
        print('Public Key: ',self.PublicKey)
        #Elliptic Curve Diffie-Hellman Key Exchange System
    def ECDH(self):
        def compressPionts(publicKey):
            return hex(publicKey.x) + hex(publicKey.y % 2)[2:] # compressing the x,y points together

        Ellipticcurve = registry.get_curve('brainpoolP256r1') # selecting a curve to encrypt on it (y^2 = x^3 + Ax + B)
        A = secrets.randbelow(Ellipticcurve.field.n) #Randmo A value
        X = A * Ellipticcurve.g # Calculate X value
        print("X:", compressPionts(X)) # compress X value
        B = secrets.randbelow(Ellipticcurve.field.n)#Randmo B value
        Y = B * Ellipticcurve.g # Calculate Y value
        print("Y:", compressPionts(Y)) # compress Y value
        print("Exchanging Keys......")
        SharedKey_A = A * Y # Calculate Shared Key (A)
        print("shared key (A) :", compressPionts(SharedKey_A))# compress Shared Key (A) value
        SharedKey_B = B * X # Calculate Shared Key (B)
        print("shared key (B) :", compressPionts(SharedKey_B))# compress Shared Key (B) value
        print("Equal shared keys:", SharedKey_A == SharedKey_B)# Verify Equality between shared keys
    # The main ECC encryption method
    def encryptECC(self,data):

        Cipher = encrypt(self.PublicKey, data) # this method consist of the public key and the data in bytes format
        return Cipher

    # The main ECC decryption method
    def decryptECC(self,Cipher):
        try:
            PlainText = decrypt(self.PrivateKey, Cipher)# this method consist of the private key and the data in bytes format
            return PlainText
        except Exception as e:
            print('Signature was manipulated !! \n\n Aborting')
    #Signature for the ECC Cipher
    def Signature(self,Cipher):
        md5 = hashlib.md5(Cipher).hexdigest() # calculate md5sum
        md5 = bytes(md5,'utf-8')#convert md5 into bytes
        sign = self.encryptECC(md5) # encrypt the signature with private key
        return sign

    # Verify Signature for the ECC Cipher
    def Signature_Verify(self,Cipher, Signature):
        md5 = self.decryptECC(Signature) # decrypt the signature with public key
        md5 = md5.decode() #decoding md5
        Cipher_hash = hashlib.md5(Cipher).hexdigest() # calculate md5sum for the cipher
        if md5 == Cipher_hash: #verify
            return True,md5,Cipher_hash
        else:
            return False,False,False


ecc = EC()
choice = ''
while choice != '4':
    meesage = '[+]Hello[+]\n===================================================================== \n> this is a program to encrypt & decrypt using Elliptic Curve Cryptograpy\n> [+] 1- Encrypt a File \n> [+] 2- Decrypt a File \n> [+] 3- ECDH\n> [-] 4- Quit \n====================================================================='
    print(meesage)
    choice = input('---> ')
    if choice == '1':
        path = str(filedialog.askopenfilename(initialdir=get_Desktop(), title='Select a file to Encrypt')).strip()

        with open(path,'rb+') as file:
            Cipher = ecc.encryptECC(file.read())
            with open(path,'wb+') as change:
                change.write(Cipher)
                change.write(ecc.Signature(Cipher))
            print('Encrypted message: ', binascii.hexlify(Cipher).decode())
            Signature = ecc.Signature(Cipher)
            print('Signature: ', binascii.hexlify(Signature).decode())
            Verify,SignVer,CipherVer = ecc.Signature_Verify(Cipher,Signature)
            print('Verify Signature: ', Verify)
            print('Signature:  ', SignVer)
            print('Cipher MD5: ', CipherVer)
    if choice =='2':
        path = str(filedialog.askopenfilename(initialdir=get_Desktop(), title='Select a file to Encrypt')).strip()
        with open(path,'rb+') as file:
            PlainText = ecc.decryptECC(file.read())
            try:
                with open(path, 'w+') as Plain:
                    Plain.write(PlainText.decode())
                print('Decrypted message: ', PlainText.decode())


                with open(path,'w+') as Plain:
                    Plain.write(PlainText.decode())
                    print('Decrypted message: ', PlainText.decode())
            except Exception as e:
                pass
    if choice == '3':
        ecc.ECDH()
    if choice == '4':
        print("Warning, if you Quit, your encrypted file will not be decrypted because in every time this program runs, a new key pair is generated !!")
        warned = input("[Y]es Quit , [N]o don't Quit : ")
        if warned == 'Y':
            break
        else:
            pass

