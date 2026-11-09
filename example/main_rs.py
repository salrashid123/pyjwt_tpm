from tpm2_pytss import *

from pyjwt_tpm import TPMSigner, SigningAlgorithm, TPMKey
from pyjwt_tpm.policy import PCRPolicy, PCRAuthValuePolicy

import jwt

import argparse

parser = argparse.ArgumentParser(description='python JWT TPM')
parser.add_argument("--tcti", default='swtpm:port=2321') # default='device:/dev/tpmrm0')
parser.add_argument("--keyfile", default='keys/rsa_key.pem')

args = parser.parse_args()

pc = TPMSigner(tcti=args.tcti, algorithm=SigningAlgorithm.RS256)
k = TPMKey(keyfile=args.keyfile)

pc.flush_tpm_handles()

jws_instance = jwt.PyJWS()
jws_instance.unregister_algorithm("RS256")
jws_instance.register_algorithm("RS256", pc)


jwt_instance = jwt.PyJWT()
jwt_instance._jws = jws_instance 

payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}

try:
    token = jwt_instance.encode(
        payload, 
        key=k, 
        algorithm="RS256"
    )
    print(token)

    public_key = k.public_pem()
    print(public_key)

    payload = jwt_instance.decode(jwt=token, key=k, algorithms=["RS256"])
    print("Token verified successfully!")
    print(payload)

    ### note, you can validate with just the RSA Public key
    decoded_payload = jwt.decode(
        token,
        public_key,
        algorithms=["RS256"]
    )
except Exception as e:
    print(e)
