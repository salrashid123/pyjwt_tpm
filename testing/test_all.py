#!/usr/bin/python

import tempfile
from tpm2_pytss import *
from pyjwt_tpm import TPMSigner, SigningAlgorithm, TPMKey
from pyjwt_tpm.policy import PCRPolicy, PCRAuthValuePolicy

from tpm2_pytss.tsskey import TSSPrivKey


from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

import jwt
from jwt.algorithms import RSAAlgorithm
from jwt.api_jws import PyJWS

import os
import unittest

swtpm = "swtpm:port=2321"


_parent_ecc_template = TPMT_PUBLIC(
    type=TPM2_ALG.ECC,
    nameAlg=TPM2_ALG.SHA256,
    objectAttributes=TPMA_OBJECT.USERWITHAUTH
    | TPMA_OBJECT.RESTRICTED
    | TPMA_OBJECT.DECRYPT
    | TPMA_OBJECT.NODA
    | TPMA_OBJECT.FIXEDTPM
    | TPMA_OBJECT.FIXEDPARENT
    | TPMA_OBJECT.SENSITIVEDATAORIGIN,
    authPolicy=b"",
    parameters=TPMU_PUBLIC_PARMS(
        eccDetail=TPMS_ECC_PARMS(
            symmetric=TPMT_SYM_DEF_OBJECT(
                algorithm=TPM2_ALG.AES,
                keyBits=TPMU_SYM_KEY_BITS(aes=128),
                mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
            ),
            scheme=TPMT_ECC_SCHEME(scheme=TPM2_ALG.NULL),
            curveID=TPM2_ECC.NIST_P256,
            kdf=TPMT_KDF_SCHEME(scheme=TPM2_ALG.NULL),
        ),
    ),
)


class TestSignVerify(unittest.TestCase):

  def testRS256(self):

    ectx = ESAPI(tcti=swtpm)
    ectx.startup(TPM2_SU.CLEAR)

    inPublic = TPM2B_PUBLIC(
                TPMT_PUBLIC.parse(
                    alg="rsa2048:rsassa:null",
                    objectAttributes=TPMA_OBJECT.USERWITHAUTH
                    | TPMA_OBJECT.FIXEDPARENT
                    | TPMA_OBJECT.FIXEDTPM
                    | TPMA_OBJECT.SENSITIVEDATAORIGIN
                    | TPMA_OBJECT.SIGN_ENCRYPT,
                )
    )

    inSensitive = TPM2B_SENSITIVE_CREATE()

    primary1, parent, _, _, _ = ectx.create_primary(inSensitive,  TPM2B_PUBLIC(publicArea=_parent_ecc_template))
    priv, pub, _, _, _ = ectx.create(primary1, inSensitive, inPublic)

    kc = TSSPrivKey(private=priv,public=pub, empty_auth=True,parent=primary1)

    ectx.flush_context(primary1)

    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=".pem") as tmp_file:
        tmp_file.write(kc.to_pem().decode("utf-8"))
        tmp_file_path = tmp_file.name    


    pc = TPMSigner(tcti=swtpm, algorithm=SigningAlgorithm.RS256)

    k = TPMKey(keyfile=tmp_file_path)

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

    payload = jwt_instance.decode(jwt=token, key=k, algorithms=["RS256", 'PS256', 'ES256'])

    ectx.close()

  def testPS256(self):

    ectx = ESAPI(tcti=swtpm)
    ectx.startup(TPM2_SU.CLEAR)

    inPublic = TPM2B_PUBLIC(
                TPMT_PUBLIC.parse(
                    alg="rsa2048:rsapss:null",
                    objectAttributes=TPMA_OBJECT.USERWITHAUTH
                    | TPMA_OBJECT.FIXEDPARENT
                    | TPMA_OBJECT.FIXEDTPM
                    | TPMA_OBJECT.SENSITIVEDATAORIGIN
                    | TPMA_OBJECT.SIGN_ENCRYPT,
                )
    )

    inSensitive = TPM2B_SENSITIVE_CREATE()

    primary1, parent, _, _, _ = ectx.create_primary(inSensitive,  TPM2B_PUBLIC(publicArea=_parent_ecc_template))
    priv, pub, _, _, _ = ectx.create(primary1, inSensitive, inPublic)

    kc = TSSPrivKey(private=priv,public=pub, empty_auth=True,parent=primary1)

    ectx.flush_context(primary1)

    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=".pem") as tmp_file:
        tmp_file.write(kc.to_pem().decode("utf-8"))
        tmp_file_path = tmp_file.name    


    pc = TPMSigner(tcti=swtpm, algorithm=SigningAlgorithm.PS256)

    k = TPMKey(keyfile=tmp_file_path)

    jws_instance = jwt.PyJWS()
    jws_instance.unregister_algorithm("PS256")
    jws_instance.register_algorithm("PS256", pc)

    jwt_instance = jwt.PyJWT()
    jwt_instance._jws = jws_instance 

    payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}

    token = jwt_instance.encode(
        payload, 
        key=k, 
        algorithm="PS256"
    )

    payload = jwt_instance.decode(jwt=token, key=k, algorithms=["RS256", 'PS256', 'ES256'])

    ectx.close() 

  def testES256(self):

    ectx = ESAPI(tcti=swtpm)
    ectx.startup(TPM2_SU.CLEAR)

    inPublic = TPM2B_PUBLIC(
                TPMT_PUBLIC.parse(
                    alg="ecc:ecdsa",
                    objectAttributes=TPMA_OBJECT.USERWITHAUTH
                    | TPMA_OBJECT.FIXEDPARENT
                    | TPMA_OBJECT.FIXEDTPM
                    | TPMA_OBJECT.SENSITIVEDATAORIGIN
                    | TPMA_OBJECT.SIGN_ENCRYPT,
                )
    )

    inSensitive = TPM2B_SENSITIVE_CREATE()

    primary1, parent, _, _, _ = ectx.create_primary(inSensitive,  TPM2B_PUBLIC(publicArea=_parent_ecc_template))
    priv, pub, _, _, _ = ectx.create(primary1, inSensitive, inPublic)

    kc = TSSPrivKey(private=priv,public=pub, empty_auth=True,parent=primary1)

    ectx.flush_context(primary1)

    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=".pem") as tmp_file:
        tmp_file.write(kc.to_pem().decode("utf-8"))
        tmp_file_path = tmp_file.name    


    pc = TPMSigner(tcti=swtpm, algorithm=SigningAlgorithm.ES256)

    k = TPMKey(keyfile=tmp_file_path)

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

    payload = jwt_instance.decode(jwt=token, key=k, algorithms=["RS256", 'PS256', 'ES256'])

    ectx.close() 

if __name__ == "__main__":
    unittest.main()    