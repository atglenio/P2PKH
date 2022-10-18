import json
import hashlib
import os
from ecdsa import SigningKey, VerifyingKey, NIST192p

#Check if files exist
#check keys
skeyExists = os.path.exists("sk.txt")
pkeyExists = os.path.exists("pk.txt")	
keysComplete = skeyExists and pkeyExists

#check blocks
block100Exists = os.path.exists("block100.json")
block101Exists = os.path.exists("block101.json")
blocksComplete = block100Exists and block101Exists

if(keysComplete and blocksComplete):
	#File reading
	f = open("sk.txt", 'rb')
	sk = SigningKey.from_string(f.read(), curve=NIST192p)
	f.close()

	in_pk = open("pk.txt", 'rb')
	pk_inString = in_pk.read()
	pk = VerifyingKey.from_string(pk_inString, curve=NIST192p)
	in_pk.close()
	
	#Script reconstruction

	#Modify the block 100
	hashval_A = hashlib.sha1(pk_inString).hexdigest() #Hash value of public/verification key

	fr = open("block100.json", "r+")
	data100 = json.load(fr)
	print("Block 100 before reconstruction")
	print(json.dumps(data100, indent = 4, sort_keys = True))
	
	#Replace [A] in scriptPubkey
	a = data100["Output"]["scriptPubKey"]
	a = a.replace("[A]", hashval_A) 
	data100["Output"]["scriptPubKey"] = a

	#Convert json object to string
	string_b100 = json.dumps(data100, indent = 4, sort_keys = True)
	print("Block 100 after reconstruction")	
	print(string_b100)

	#Rewrite the file with new script
	fr.seek(0)
	fr.write(string_b100)
	fr.truncate()
	fr.close()

	#Modify the block 101
	fr = open("block101.json", "r+")
	data101 =json.load(fr)
	print("Block 101 before reconstruction")
	print(json.dumps(data101, indent = 4, sort_keys = True))

	#Replace [B]
	hashval_B = hashlib.sha256(string_b100.encode()).hexdigest()
	data101["Input"]["Previous tx"] = hashval_B

	#Replace [C]
	signature = sk.sign(hashval_B.encode())
	signature = signature.hex()
	data101["Input"]["scriptSig"][0] = signature;

	#Replace [D]
	data101["Input"]["scriptSig"][1] = pk_inString.hex()

	#Convert json object to string
	string_b101 = json.dumps(data101, indent = 4, sort_keys = True)	
	print("Block 101 after reconstruction")	
	print(string_b101)

	#Rewrite the file with new script
	fr.seek(0)
	fr.write(string_b101)
	fr.truncate()
	fr.close()
else:
	print("Files are not complete")

