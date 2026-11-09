from tpm2_pytss import *

from pyjwt_tpm import TPMSigner, SigningAlgorithm, TPMKey
from pyjwt_tpm.policy import PCRPolicy, PCRAuthValuePolicy

import jwt
from jwt.algorithms import RSAAlgorithm
from jwt.api_jws import PyJWS

import argparse

parser = argparse.ArgumentParser(description='python JWT TPM')
parser.add_argument("--tcti", default='swtpm:port=2321') # default='device:/dev/tpmrm0')
parser.add_argument("--keyfile", default='keys/rsa_key.pem')
parser.add_argument("--enc_key_name", default='000bfcfb59368b19aae7d961247d56ad0f5264ef284e8339b590c3f34b99ce18aba2')

args = parser.parse_args()

pc = TPMSigner(tcti=args.tcti, algorithm=SigningAlgorithm.RS256, enc_key_name=args.enc_key_name)

k = TPMKey(keyfile=args.keyfile)

jws_instance = jwt.PyJWS()
jws_instance.unregister_algorithm("RS256")
jws_instance.register_algorithm("RS256", pc)


jwt_instance = jwt.PyJWT()
jwt_instance._jws = jws_instance 

payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}

token = jwt_instance.encode(
    payload, 
    key=k, 
    algorithm="RS256"
)
print(token)

public_key = k.public_pem()
print(public_key)

payload = jwt_instance.decode(jwt=token, key=k, algorithms=["RS256", 'PS256', 'ES256'])
print("Token verified successfully!")
print(payload)
    