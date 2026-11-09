from tpm2_pytss import *

from pyjwt_tpm import TPMSigner, SigningAlgorithm, TPMKey
from pyjwt_tpm.policy import PCRPolicy, PCRAuthValuePolicy, PolicyORAndDuplicateSelectPolicy

import jwt
from jwt.algorithms import RSAAlgorithm
from jwt.api_jws import PyJWS
from tpm2_pytss.internal.templates import ek_rsa2048

import argparse

parser = argparse.ArgumentParser(description='python JWT TPM')
parser.add_argument("--tcti", default='swtpm:port=2321') # default='device:/dev/tpmrm0')
parser.add_argument("--keyfile", default='keys/rsa_key_dupliate.pem')
parser.add_argument("--ownerpassword", default='')
parser.add_argument("--password", default='')
parser.add_argument("--ek_name", default='') # 000bfcfb59368b19aae7d961247d56ad0f5264ef284e8339b590c3f34b99ce18aba2

args = parser.parse_args()


if args.ek_name == '':
    ectx = ESAPI(tcti=args.tcti)
    ectx.startup(TPM2_SU.CLEAR)
    def setup_ek_session(ectx):
        sym = TPMT_SYM_DEF(
            algorithm=TPM2_ALG.XOR,
            keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )
        session = ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.POLICY,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )
        nonce = ectx.trsess_get_nonce_tpm(session)
        expiration = -(10 * 365 * 24 * 60 * 60)
        ectx.policy_secret(ESYS_TR.ENDORSEMENT, session, nonce, b"", b"", expiration
        )
        ectx.trsess_set_attributes(session, TPMA_SESSION.ENCRYPT | TPMA_SESSION.DECRYPT)
        return session

    tmpl = ek_rsa2048.template

    inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH(args.ownerpassword))) 
    ek_handle, ek_pub, _, _, _ = ectx.create_primary(
        inSensitive, tmpl, ESYS_TR.ENDORSEMENT)

    args.ek_name = ek_pub.get_name()
    ectx.flush_context(ek_handle)
    ectx.close()    


policy_impl = None

pol={
    "name": "MyPolicyOR",
    "description":"Policy OR",
    "policy": [
        {
         "type": "or",
            "branches": [ 
                 {
                    "name": "authvalue",
                    "description":"Policy AuthValue",
                    "policy": [
                        {
                            "type": "authValue",
                        }
                    ]    
                },
                {
                    "name": "duplicationSelect",
                    "description":"Policy DuplicateSelect",
                    "policy": [
                        {
                            "type": "duplicationSelect",
                            "newParentName": "{}".format(args.ek_name),
                        }
                    ]    
                },                
            ],
        },
    ],
}


policy_impl = PolicyORAndDuplicateSelectPolicy(policy=pol)

pc = TPMSigner(tcti=args.tcti, algorithm=SigningAlgorithm.RS256)

k = TPMKey(keyfile=args.keyfile, ownerpassword=args.ownerpassword, password=args.password,policy_impl=policy_impl, use_ek_cert=True)

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


payload = jwt_instance.decode(jwt=token, key=k, algorithms=["RS256"])
print("Token verified successfully!")
print(payload)
    