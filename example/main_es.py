from tpm2_pytss import *

from pyjwt_tpm import TPMSigner, SigningAlgorithm, TPMKey
from pyjwt_tpm.policy import PCRPolicy, PCRAuthValuePolicy

import jwt
from jwt.algorithms import RSAAlgorithm
from jwt.api_jws import PyJWS

import argparse

parser = argparse.ArgumentParser(description='python JWT TPM')
parser.add_argument("--tcti", default='swtpm:port=2321') # default='device:/dev/tpmrm0')
parser.add_argument("--keyfile", default='keys/ecc_key.pem')

args = parser.parse_args()

pc = TPMSigner(tcti=args.tcti,
               algorithm=SigningAlgorithm.ES256)

k = TPMKey(keyfile=args.keyfile,  name="mykey")

jws_instance = jwt.PyJWS()
jws_instance.unregister_algorithm("ES256")
jws_instance.register_algorithm("ES256", pc)

jwt_instance = jwt.PyJWT()
jwt_instance._jws = jws_instance 

payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}

token = jwt_instance.encode(
    payload, 
    key=k, 
    algorithm="ES256"
)
print(token)

public_key = k.public_pem()
print(public_key)

payload = jwt_instance.decode(jwt=token, key=k, algorithms=['ES256'])
print("Token verified successfully!")
print(payload)
    