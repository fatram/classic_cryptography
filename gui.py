import tkinter as tk
from tkinter.filedialog import askopenfilename
from classic import *

def encryptButton():
    selected = listCipher.get(listCipher.curselection())
    message = textPlaintext.get("1.0", tk.END).rstrip().upper()
    key = textKey.get("1.0", tk.END).rstrip().upper()
    key2 = textKey2.get("1.0", tk.END).rstrip().upper()
    ciphertext = ""
    if(selected == "Vigenere"):
        ciphertext = Vigenere.encrypt(message, key)
    elif(selected == "Full Vigenere"):
        ciphertext = FullVigenere.encrypt(message, key, FullVigenere.makeTable())
    elif(selected == "Auto Key Vigenere"):
        ciphertext = AutoKeyVigenere.encrypt(message, key)
    elif(selected == "Extended Vigenere"):
        ciphertext = ExtendedVigenere.encrypt(message, key)
    elif(selected == "Affine"):
        ciphertext = Affine.encrypt(message, (int(s) for s in key.split()))
    elif(selected == "Playfair"):
        ciphertext = Playfair.encrypt(message, Playfair.buildtable(key.upper()))
    elif(selected == "Super Encryption (Vigenere + Transposition)"):
        ciphertext = SuperEncryption.encrypt(message, key, int(key2))
    elif(selected == "Hill"):
        ciphertext = Hill.encrypt(message, Hill.generateMatrix())
    else:
        pass
    textCiphertext.delete("1.0", tk.END)
    textCiphertext.insert(tk.END, ciphertext)

def encryptButtonFile():
    inittext = textPlaintext.get("1.0", tk.END).rstrip()
    inittext.replace(" ","")
    if(listMisc.get(listMisc.curselection()) == "Five letters group"):
        textPlaintext.insert(tk.END, groupMessagePerFiveCharacter(inittext))
    else:
        textPlaintext.insert(tk.END, inittext)
    selected = listCipher.get(listCipher.curselection())
    message = readFileText(labelPlaintextFile['text'])
    key = textKey.get("1.0", tk.END).rstrip().upper()
    key2 = textKey2.get("1.0", tk.END).rstrip().upper()
    ciphertext = ""
    if(selected == "Vigenere"):
        ciphertext = Vigenere.encrypt(message, key)
    elif(selected == "Full Vigenere"):
        ciphertext = FullVigenere.encrypt(message, key, FullVigenere.makeTable())
    elif(selected == "Auto Key Vigenere"):
        ciphertext = AutoKeyVigenere.encrypt(message, key)
    elif(selected == "Extended Vigenere"):
        ciphertext = ExtendedVigenere.encrypt(message, key)
    elif(selected == "Affine"):
        ciphertext = Affine.encrypt(message, (int(s) for s in key.split()))
    elif(selected == "Playfair"):
        ciphertext = Playfair.encrypt(message, Playfair.buildtable(key.upper()))
    elif(selected == "Super Encryption (Vigenere + Transposition)"):
        ciphertext = SuperEncryption.encrypt(message, key, int(key2))
    elif(selected == "Hill"):
        ciphertext = Hill.encrypt(message, Hill.generateMatrix())
    else:
        pass
    textCiphertext.delete("1.0", tk.END)
    textCiphertext.insert(tk.END, ciphertext)

def encryptButtonFileBinary():
    message = readFileBinary(labelPlaintextFile['text'])
    key = textKey.get("1.0", tk.END).rstrip().upper()
    ciphertext = ExtendedVigenere.encrypt(message, key)
    textCiphertext.delete("1.0", tk.END)
    textCiphertext.insert(tk.END, "FILE BINARY MAY BECOME UNREADABLE AS A TEXT, THEREFORE THE RESULT WILL BE SAVED TO THE COMPUTER AUTOMATICALLY")
    writeFileBinary("encrypted", ciphertext)

def decryptButton():
    selected = listCipher.get(listCipher.curselection())
    message = textCiphertext.get("1.0", tk.END).rstrip().upper()
    key = textKey.get("1.0", tk.END).rstrip().upper()
    key2 = textKey2.get("1.0", tk.END).rstrip().upper()
    plaintext = ""
    if(selected == "Vigenere"):
        plaintext = Vigenere.decrypt(message, key)
    elif(selected == "Full Vigenere"):
        plaintext = FullVigenere.decrypt(message, key, FullVigenere.makeTable())
    elif(selected == "Auto Key Vigenere"):
        plaintext = AutoKeyVigenere.decrypt(message, key)
    elif(selected == "Extended Vigenere"):
        plaintext = ExtendedVigenere.decrypt(message, key)
    elif(selected == "Affine"):
        plaintext = Affine.decrypt(message, (int(s) for s in key.split()))
    elif(selected == "Playfair"):
        plaintext = Playfair.decrypt(message, Playfair.buildtable(key.upper()))
    elif(selected == "Super Encryption (Vigenere + Transposition)"):
        plaintext = SuperEncryption.decrypt(message, key, int(key2))
    elif(selected == "Hill"):
        ciphertext = Hill.decrypt(message, Hill.generateMatrix())
    else:
        pass
    textPlaintext.delete("1.0", tk.END)
    textPlaintext.insert(tk.END, plaintext)

def decryptButtonFile():
    inittext = textPlaintext.get("1.0", tk.END).rstrip()
    inittext.replace(" ","")
    if(listMisc.get(listMisc.curselection()) == "Five letters group"):
        textPlaintext.insert(tk.END, groupMessagePerFiveCharacter(inittext))
    else:
        textPlaintext.insert(tk.END, inittext)
    selected = listCipher.get(listCipher.curselection())
    message = readFileText(labelCiphertextFile['text'])
    key = textKey.get("1.0", tk.END).rstrip().upper()
    key2 = textKey2.get("1.0", tk.END).rstrip().upper()
    plaintext = ""
    if(selected == "Vigenere"):
        plaintext = Vigenere.decrypt(message, key)
    elif(selected == "Full Vigenere"):
        plaintext = FullVigenere.decrypt(message, key, FullVigenere.makeTable())
    elif(selected == "Auto Key Vigenere"):
        plaintext = AutoKeyVigenere.decrypt(message, key)
    elif(selected == "Extended Vigenere"):
        plaintext = ExtendedVigenere.decrypt(message, key)
    elif(selected == "Affine"):
        plaintext = Affine.decrypt(message, (int(s) for s in key.split()))
    elif(selected == "Playfair"):
        plaintext = Playfair.decrypt(message, Playfair.buildtable(key.upper()))
    elif(selected == "Super Encryption (Vigenere + Transposition)"):
        plaintext = SuperEncryption.decrypt(message, key, int(key2))
    elif(selected == "Hill"):
        ciphertext = Hill.decrypt(message, Hill.generateMatrix())
    else:
        pass
    textPlaintext.delete("1.0", tk.END)
    textPlaintext.insert(tk.END, plaintext)
        

def decryptButtonFileBinary():
    message = readFileBinary(labelCiphertextFile['text'])
    key = textKey.get("1.0", tk.END).rstrip().upper()
    plaintext = ExtendedVigenere.encrypt(message, ExtendedVigenere.generateKey(readFileBinary(labelPlaintextFile['text']), key))
    textPlaintext.delete("1.0", tk.END)
    textPlaintext.insert(tk.END, "FILE BINARY MAY BECOME UNREADABLE AS A TEXT, THEREFORE THE RESULT WILL BE SAVED TO THE COMPUTER AUTOMATICALLY")
    writeFileBinary("decrypted", plaintext)

def openFileEncryption():
    filepath = askopenfilename()
    if not filepath:
        return
    labelPlaintextFile['text'] = filepath

def openFileDecryption():
    filepath = askopenfilename()
    if not filepath:
        return
    labelCiphertextFile['text'] = filepath

def saveFileEncryption():
    message = textCiphertext.get("1.0", tk.END).rstrip().upper()
    writeFileText("decrypted.txt", message)

def saveFileDecryption():
    message = textPlaintext.get("1.0", tk.END).rstrip().upper()
    writeFileText("encrypted.txt", message)

window = tk.Tk()
window.title("Classic Cryptography")

frameChooseCipher = tk.Frame(master=window, width=100, height=20, bg="white")
labelChooseCipher = tk.Label(master=frameChooseCipher, text="Choose encryption method", background="white")
labelChooseCipher.grid(row=0, column=0)
listCipher = tk.Listbox(master=frameChooseCipher, selectmode="single")
listCipher.grid(row=0, column=1)
ciphers = ["Vigenere", "Full Vigenere", "Auto Key Vigenere", "Extended Vigenere", "Affine", 
     "Playfair", "Super Encryption (Vigenere + Transposition)", "Hill"] 
for cipher in ciphers: 
    listCipher.insert(tk.END, cipher) 
frameChooseCipher.grid(row=0, column=0, padx=5, pady=5)
frameMisc = tk.Frame(master=window, width=100, height=20, bg="white")
listMisc = tk.Listbox(master=frameMisc, selectmode="single")
listMisc.pack()
miscs = ["No space", "Five letters group"]
for misc in miscs:
    listMisc.insert(tk.END, misc)
frameMisc.grid(row=0, column=1, padx=5, pady=5)


framePlaintext = tk.Frame(master=window, width=100, height=100, bg="white")
labelPlaintext = tk.Label(master=framePlaintext, text="View/insert your Plaintext here", background="white")
labelPlaintext.pack()
textPlaintext = tk.Text(master=framePlaintext, height="20")
textPlaintext.pack()
buttonPlaintext = tk.Button(master=framePlaintext, text="Encrypt", command=encryptButton)
buttonPlaintext.pack()
buttonPlaintextFileEncrypt = tk.Button(master=framePlaintext, text="Encrypt file text", command=encryptButtonFile)
buttonPlaintextFileEncrypt.pack()
buttonPlaintextFileEncryptBinary = tk.Button(master=framePlaintext, text="Encrypt file binary", command=encryptButtonFileBinary)
buttonPlaintextFileEncryptBinary.pack()
buttonPlaintextSave = tk.Button(master=framePlaintext, text="Save encrypted file/text", command=saveFileEncryption)
buttonPlaintextSave.pack()
buttonPlaintextFile = tk.Button(master=framePlaintext, text="Import file Plaintext", command=openFileEncryption)
buttonPlaintextFile.pack()
labelPlaintextFile = tk.Label(master=framePlaintext, text="No file", background="white")
labelPlaintextFile.pack()
framePlaintext.grid(row=1, column=0, padx=5, pady=5)

frameCiphertext = tk.Frame(master=window, width=100, height=100, bg="white")
labelCiphertext = tk.Label(master=frameCiphertext, text="View/insert your Ciphertext here", background="white")
labelCiphertext.pack()
textCiphertext = tk.Text(master=frameCiphertext, height="20")
textCiphertext.pack()
buttonCiphertext = tk.Button(master=frameCiphertext, text="Decrypt", command=decryptButton)
buttonCiphertext.pack()
buttonCiphertextFileEncrypt = tk.Button(master=frameCiphertext, text="Decrypt file text", command=decryptButtonFile)
buttonCiphertextFileEncrypt.pack()
buttonCiphertextFileEncryptBinary = tk.Button(master=frameCiphertext, text="Decrypt file binary", command=decryptButtonFileBinary)
buttonCiphertextFileEncryptBinary.pack()
buttonCiphertextSave = tk.Button(master=frameCiphertext, text="Save decrypted file/text", command=saveFileDecryption)
buttonCiphertextSave.pack()
buttonCiphertextFile = tk.Button(master=frameCiphertext, text="Import file Ciphertext", command=openFileDecryption)
buttonCiphertextFile.pack()
labelCiphertextFile = tk.Label(master=frameCiphertext, text="No file", background="white")
labelCiphertextFile.pack()
frameCiphertext.grid(row=1, column=1, padx=5, pady=5)

frameKey = tk.Frame(master=window, width=100, height=20, bg="white")
labelKey = tk.Label(master=frameKey, text="Write key", background="white")
labelKey.grid(row=0, column=0)
textKey = tk.Text(master=frameKey, height=10, width=30)
textKey.grid(row=0, column=1)
textKey2 = tk.Text(master=frameKey, height=10, width=30)
textKey2.grid(row=0, column=2)
frameKey.grid(row=2, column=0, padx=5, pady=5)

window.mainloop()