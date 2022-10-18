import ecdsa
import hashlib

#Q1
sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST192p)
pk = sk.get_verifying_key()

#Generate secret key
out_sk = open("sk" + ".txt", "w+b")
sk = sk.to_string()
out_sk.write(sk)
out_sk.close()

#Generate public key
out_pk = open("pk" + ".txt", "w+b")
pk = pk.to_string()
out_pk.write(pk)
out_pk.close()

print("Account key pair generated")
