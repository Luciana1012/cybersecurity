def ceaserDecrypt():
    with open("Textfile.txt", "w") as f:
        f.write("This is a test")
    with open("C:/Users/hitoc/caesarEncrypted", "r") as f:
        cipherText = f.read()
        print(cipherText)
    result = ""
   # for i in range (0, len(ciphertext)):
    #    character = ciphertext[i]
     #   result += chr((ord(character) - 9
      #   - 97) % 26 + 97)
    #return result

ceaserDecrypt()