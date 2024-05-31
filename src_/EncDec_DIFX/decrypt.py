from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = b'<predefined key>'

with open('DIFX.txt', 'rb') as fp:
	encrypted = fp.read()
decipher = AES.new(key, AES.MODE_ECB)
data_back = decipher.decrypt(encrypted)

with open("decoded_output.cpp", 'w') as bp:
	bp.write(data_back.decode())
