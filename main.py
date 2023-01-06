from tkinter import *
from tkinter import messagebox
import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.hashes import SHA256



def encrypt_pressed():

    global  ciphertext, cipherkey, private_key

    #checking user's password
    password=code.get()
    if password=="pass":

        # recipient private key
        private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
        )

        # public key
        public_key = private_key.public_key()

        # Plaintext to encrypt
        message=text1.get(1.0,END)
        plaintext= message.encode(encoding='utf8') 

        # encrypt plaintext
        ciphertext, cipherkey = encrypt(plaintext, public_key)
        
        text1.delete(1.0,END)
        text1.insert(END,ciphertext)

    elif password=="":
        messagebox.showerror("Attention", "Please Enter Your Password")
    elif password !="pass":
        messagebox.showerror("Attention", "Invalid Password")


def encrypt(plaintext, public_key):

    # Pad the plaintext
    pkcs7_padder = padding.PKCS7(AES.block_size).padder()
    padded_plaintext = pkcs7_padder.update(plaintext) + pkcs7_padder.finalize()
       
    # Generate new random AES-256 key
    key = os.urandom(256 // 8)

    # Generate new random 128 IV required for CBC mode
    iv = os.urandom(128 // 8)

    # AES CBC Cipher
    aes_cbc_cipher = Cipher(AES(key), CBC(iv))

    # Encrypt padded plaintext
    ciphertext = aes_cbc_cipher.encryptor().update(padded_plaintext)
        
    # Encrypt AES key using recipient's public key
    oaep_padding = asymmetric_padding.OAEP(mgf=asymmetric_padding.MGF1(algorithm=SHA256()), algorithm=SHA256(), label=None)
    cipherkey = public_key.encrypt(key, oaep_padding)
    
    return {'iv':iv, 'ciphertext': ciphertext}, cipherkey   


def decrypt_pressed():

    password=code.get()
    if password=="pass":

        recovered_plaintext= decrypt(ciphertext, cipherkey, private_key)

        text1.delete(1.0,END)
        text1.insert(END,recovered_plaintext)
    
    elif password=="":
        messagebox.showerror("Attention", "Please Enter Your Password")
    elif password !="pass":
        messagebox.showerror("Attention", "Invalid Password")


def decrypt(ciphertext, cipherkey, private_key):
    
    # Decrypt AES key
    oaep_padding = asymmetric_padding.OAEP(mgf=asymmetric_padding.MGF1(algorithm=SHA256()), algorithm=SHA256(), label=None)
    recovered_key = private_key.decrypt(cipherkey, oaep_padding)

    # Decrypt padded plaintext
    aes_cbc_cipher = Cipher(AES(recovered_key), CBC(ciphertext['iv']))
    recovered_padded_plaintext = aes_cbc_cipher.decryptor().update(ciphertext['ciphertext'])

    # Remove padding
    pkcs7_unpadder = padding.PKCS7(AES.block_size).unpadder()
    recovered_plaintext = pkcs7_unpadder.update(recovered_padded_plaintext) + pkcs7_unpadder.finalize()

    return recovered_plaintext


def main_screen():

    global screen
    global code
    global text1

    screen=Tk()
    screen.geometry("500x550")
    screen.title("Privacy")

    def reset():
        code.set("")
        text1.delete(1.0,END)

    Label(text="Enter your message",fg="#0000FF",font=("calbri", 14)).place(x=20,y=20)
    text1=Text(font="Robote 20",  bg="white", relief=GROOVE, wrap=WORD,bd=0)
    text1.place(x=20, y=70, width=460, height=150)
    Label(text="Enter your password",fg="#0000FF",font=("calbri", 14)).place(x=20,y=240)

    code=StringVar()
    Entry(textvariable=code,width=19, bd=0, font=("arial",20),show="*").place(x=20, y=280)

    Button(text="Encrypt",height="2",width=17, bg="green",fg="white",bd=0,font=("calbri", 14, "bold"),command=encrypt_pressed).place(x=20, y=350)
    Button(text="Decrypt",height="2",width=17, bg="red",fg="white",bd=0,font=("calbri", 14,"bold"),command=decrypt_pressed).place(x=270, y=350)
    Button(text="Reset",height="2",width=38, bg="blue",fg="white",bd=0,font=("calbri", 14,"bold"), command=reset).place(x=20, y=440)

    screen.mainloop()

main_screen()