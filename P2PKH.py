import json
import hashlib
from ecdsa import SigningKey, VerifyingKey, NIST192p
import os

#check blocks
block100Exists = os.path.exists("block100.json")
block101Exists = os.path.exists("block101.json")
blocksComplete = block100Exists and block101Exists

if(blocksComplete):
	#Read block100
	in_file = open("block100.json", "r+")
	data100 = json.load(in_file)
	data100_str = json.dumps(data100, indent = 4, sort_keys = True)
	pk_b100 = data100["Output"]["scriptPubKey"]
	pk_b100 = pk_b100.split(" ")
	pk_b100 = pk_b100[2]
	in_file.close()

	#Read block101
	in_file = open("block101.json", "r+")
	data101 = json.load(in_file)
	prev_TX = data101["Input"]["Previous tx"]
	sig_str = data101["Input"]["scriptSig"][0]
	pk_str = data101["Input"]["scriptSig"][1]
	in_file.close()

	#Q3
	def is_hex(string):
		try:
			int(string, 16)
			return True
		except ValueError:
			return False

	def dupplicate(pk):
		return pk
		
	def hash160(pk):
		if(is_hex(pk) == True):
			pk = VerifyingKey.from_string(bytes.fromhex(pk), curve=NIST192p)
		
		pk_hash = hashlib.sha1(pk.to_string()).hexdigest()
		return pk_hash	
		
	def equalverify(hash1, hash2):
		print("EQUALVERIFY")
		if(hash1 == hash2):
			print("True")
			return True
		else:
			print("False")
			return False

	def checksig(pk, signature, message):
		
		if(is_hex(pk) == True):
			pk = VerifyingKey.from_string(bytes.fromhex(pk), curve=NIST192p)
			if(is_hex(signature)):
				signature = bytes.fromhex(signature)	
				return pk.verify(signature, message.encode())

	#Q4

	def print_stack(stack):
		for i in range(len(stack)-1, -1, -1):
			print(stack[i])
	
	#Get signature
	signature = bytes.fromhex(sig_str)
	#Get pubkey
	pk = VerifyingKey.from_string(bytes.fromhex(pk_str), curve=NIST192p)
		
	#P2PKH
	print("Below is LIFO output : \n")	
	stack = []
	stack.append(signature.hex())
	stack.append(pk.to_string().hex())
	print("P2PKH")
	print_stack(stack)
	print("Length: " + str(len(stack)))
	print()

	#DUPLICATE
	pk_popped = stack.pop()
	stack.append(pk_popped)
	stack.append(dupplicate(pk_popped))
	print("Dulplicate")
	print_stack(stack)
	print("Length: " + str(len(stack)))
	print()

	#HASH160
	stack.append(hash160(stack.pop()))
	print("HASH160")
	print_stack(stack)
	print("Length: " + str(len(stack)))
	print()

	#push scriptpubkey
	stack.append(pk_b100)

	#EQUALVERIFY
	if(equalverify(stack.pop(), stack.pop())):
		print()	
		#CHECKSIG
		print("CHECKSIG")
		stack.append(checksig(stack.pop(), stack.pop(), prev_TX))
		print_stack(stack)
		print("Length: " + str(len(stack)))
		print()
else:
	print("Keys is not complete")

