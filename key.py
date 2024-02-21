import secrets


def generate_8_byte_key():
    return secrets.token_bytes(8).decode()


# key_C = generate_8_byte_key()
# key_Tgs = generate_8_byte_key()
# k_V = generate_8_byte_key()
# key_Ctgs = generate_8_byte_key()
# key_Cv = generate_8_byte_key()

key_C = "01234567"
key_Tgs = "01204507"
k_V = "00110011"
key_Ctgs = "11001100"
key_Cv = "11110000"




