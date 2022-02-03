# Run "pyip install pcryptodome" in the command prompt to use Crypto
from Crypto.Hash import SHA3_256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

sign_key = ECC.generate(curve='NIST P-256')  #generate a sign key -> private key
verify_key = sign_key.public_key()           #generate a verification key ->public key out of sign key

f = open('crypto_operations.log','wt')            # open file with write mode 
f.write(verify_key.export_key(format='OpenSSH'))   #change format of keys to text cause they have special type write public key

signer = DSS.new(sign_key, 'fips-186-3')        #new signing instance

message = b'''All hushed and still within the house;
Without - all wind and driving rain;
But something whispers to my mind,
Through rain and through the wailing wind,
Never again.
Never again?
Why not again?
Memory has power as real as thine.'''
#message = b'erkay'
h = SHA3_256.new(message)                            #hash the message to h
signature = signer.sign(h)                          # call signature instance to create signature
f.write(str(int.from_bytes(signature, "big")))       # change byte to int to str write signed
f.close()

#######
# Verification Part
####### 
f = open('crypto_operations.log','rt')      #first line verification key second signature
log = f.readlines()
vkey = ECC.import_key(log[0])                      #verification key
sig = int(log[1]).to_bytes(64, byteorder='big')    # read as string then to int then byte

print("log: ", log)
print("sig: ", sig)

message_ = b'''All hushed and still within the house;
Without - all wind and driving rain;
But something whispers to my mind,
Through rain and through the wailing wind,
Never again.
Never again?
Why not again?
Memory has power as real as thine.'''
#message_ = b'erkay'
h_ = SHA3_256.new(message_)         # hash message_

verifier = DSS.new(vkey, 'fips-186-3')              #instance of verifier with verification key
try:
    verifier.verify(h_, sig)
    print ("The message is authentic.")
except ValueError:
    print ("The message is not authentic.")
