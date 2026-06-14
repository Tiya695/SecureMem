from encryption import encrypt, decrypt

original = "User prefers vegetarian food"
encrypted = encrypt(original)
decrypted = decrypt(encrypted)

print("Original :", original)
print("Encrypted:", encrypted)
print("Decrypted:", decrypted)