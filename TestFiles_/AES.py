from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

data = b'''
<keylogger raw CPP code>
'''

key = b'<prededfined 16 byte key>'

cipher = AES.new(key, AES.MODE_ECB)
data = pad(data, AES.block_size)
ciphertext = cipher.encrypt(data)

with open("DIFX.txt", 'wb') as fp:
	fp.write(ciphertext)
