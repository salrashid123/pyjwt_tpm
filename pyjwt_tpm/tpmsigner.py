from tpm2_pytss import *
from tpm2_pytss.tsskey import TSSPrivKey
from tpm2_pytss.internal.templates import ek_rsa2048

import tpm2_pytss.utils
from tpm2_pytss.constants import TPM2_ALG

from pyjwt_tpm.policy import PolicyEval
from jwt.algorithms import Algorithm

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from enum import Enum, auto
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric import ec, utils


class SigningAlgorithm(Enum):
    RS256 = 1
    PS256 = 2    
    ES256 = 3


class TPMKey(TSSPrivKey):

    def __init__(
        self,
        keyfile,
        name=None,
        ownerpassword=None,
        password=None,
        policy_impl: PolicyEval = None,
        use_ek_cert=None,        
    ):
        f = open(keyfile, "r")
        self._kb = f.read()
        f.close()
        
        k = TSSPrivKey.from_pem(self._kb.encode('utf-8'))
        super().__init__(k.private,k.public,k.empty_auth,k.parent)
        self._name = name
        self._password = password
        self._ownerpassword = ownerpassword
        self._use_ek_cert = use_ek_cert
        self._policy_impl = policy_impl

    def key_type(self) -> TPM2_ALG:
        return self.public.publicArea.type

    def key_scheme(self) -> TPM2_ALG:
        match self.key_type():
            case TPM2_ALG.RSA:
                return self.public.publicArea.parameters.rsaDetail.scheme.scheme
            case TPM2_ALG.ECC:
                return self.public.publicArea.parameters.eccDetail.scheme.scheme
            case _:
                raise Exception(f"unsupported key scheme {self.key_type()}")

    def key_hashalg(self) -> TPM2_ALG:     
        match self.key_type():
            case TPM2_ALG.RSA:
                hashAlg = self.public.publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg
            case TPM2_ALG.ECC:
                hashAlg = self.public.publicArea.parameters.eccDetail.scheme.details.anySig.hashAlg
            case _:
                raise Exception(f"unsupported key scheme {self.key_type()}")
            

        if  hashAlg == TPM2_ALG.ERROR:
            raise Exception("TPM key hash algorithm not encoded")
        return hashAlg

    def public_key(self) -> RSAPublicKey|EllipticCurvePublicKey :
        public_key = load_pem_public_key( self.public.to_pem())
        return public_key

    def public_pem(self) -> bytes :
        public_key = load_pem_public_key( self.public.to_pem())
        pem_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        return pem_bytes
            
    
class TPMSigner(Algorithm):

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

    DEFAULT_TCTI = "device:/dev/tpmrm0"

    def __init__(
        self,
        tcti,
        algorithm,
        enc_key_name=None
    ):

        self._tcti = tcti or self.DEFAULT_TCTI
        self._algorithm = algorithm
        self._enc_key_name = enc_key_name

    def prepare_key(self, key: TPMKey) -> TPMKey:
        return key
            
    def verify(self, msg: bytes, key: TPMKey, sig: bytes) -> bool:
        k = self.prepare_key(key)
        public_key = load_pem_public_key( k.public.to_pem())

    
        match self._algorithm:
            case SigningAlgorithm.RS256:
                    scheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.RSASSA)
                    hashAlg = hashes.SHA256()
            case SigningAlgorithm.PS256:
                    scheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.RSAPSS)
                    hashAlg = hashes.SHA256()                    
            case SigningAlgorithm.ES256:
                    scheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.ECDSA)
                    hashAlg = hashes.SHA256()                    
            case _:
                raise Exception("unsupported key type during verify")
        
        match k.key_type():
            case TPM2_ALG.RSA:
                match scheme.scheme:
                    case TPM2_ALG.RSASSA:    
                        try:
                            public_key.verify(
                                signature=sig,
                                data=msg,
                                padding=padding.PKCS1v15(),
                                algorithm=hashAlg
                            )
                            return True
                        except InvalidSignature:
                            return False
                    case TPM2_ALG.RSAPSS:
                        try:
                            public_key.verify(
                                signature=sig,
                                data=msg,
                                padding=padding.PSS(
                                    mgf=padding.MGF1(hashAlg),
                                    salt_length=padding.PSS.DIGEST_LENGTH
                                ),
                                algorithm=hashAlg
                            )
                            return True
                        except InvalidSignature:
                            return False
                    case _:
                        raise Exception("unsupported key scheme during verify RSA")                           
            case TPM2_ALG.ECC:
                    try:
                        r_bytes = sig[:32]
                        s_bytes = sig[32:]
                        r = int.from_bytes(r_bytes, byteorder='big')
                        s = int.from_bytes(s_bytes, byteorder='big')
                        der_signature = utils.encode_dss_signature(r, s)
                        public_key.verify(
                            signature=der_signature,
                            data=msg,
                            signature_algorithm=ec.ECDSA(hashAlg)
                        )
                        return True
                    except InvalidSignature:
                        return False
            case _:
                raise Exception("unsupported key type during verify")

    def flush_tpm_handles(self):
        try:
           ectx = ESAPI(tcti=self._tcti)
           ectx.startup(TPM2_SU.CLEAR)
        except TSS2_Exception as e:
            raise e

        for capability_base in [TPM2_HC.HR_TRANSIENT, TPM2_HC.HR_POLICY_SESSION, TPM2_HC.HR_HMAC_SESSION]: # [0x80000000, 0x02000000]:
            
            more_data = True
            current_handle = capability_base     
            while more_data:
                more_data, cap_data = ectx.get_capability(
                    capability=TPM2_CAP.HANDLES, 
                    prop=current_handle, 
                    property_count=8
                )  
                handles = cap_data.data.handles
                if not handles:
                    break
                for handle in handles:
                    esys_handle = ectx.tr_from_tpmpublic(handle)

                    ectx.flush_context(esys_handle)
        ectx.close()

    def from_jwk(self, jwk):
        raise NotImplementedError("TPM Based key cannot get deserialized")

    def to_jwk(self, key):
        raise NotImplementedError("TPM Based key cannot get serialized")
    
    def sign(self, msg: bytes, key: TPMKey) -> bytes:

        try:
           ectx = ESAPI(tcti=self._tcti)
           ectx.startup(TPM2_SU.CLEAR)
        except TSS2_Exception as e:
            raise e

        
        try:

            key_type = key.key_type()

            match key_type:
                case  TPM2_ALG.RSA:
                    if not self._algorithm in [SigningAlgorithm.RS256, SigningAlgorithm.PS256]:
                        raise Exception(f"Key type in PEM is {key_type} but requested algorithm is: {self._algorithm}")
                case  TPM2_ALG.ECC:
                    if not self._algorithm in [SigningAlgorithm.ES256]:
                        raise Exception(f"Key type in PEM is {key_type} but requested algorithm is: {self._algorithm}")                    
                case _ :
                    raise Exception(f"unsupported key type during sign {key_type}")
                
            match self._algorithm:
                case SigningAlgorithm.RS256:
                    scheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.RSASSA)
                    hashAlg = TPM2_ALG.SHA256
                case SigningAlgorithm.PS256:
                    scheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.RSAPSS)
                    hashAlg = TPM2_ALG.SHA256                       
                case SigningAlgorithm.ES256:
                    scheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.ECDSA)
                    hashAlg = TPM2_ALG.SHA256                       
                case _ :
                    raise Exception("unsupported key type during sign")
            scheme.details.any.hashAlg = hashAlg
            inSensitiveOwner = TPM2B_SENSITIVE_CREATE(TPMS_SENSITIVE_CREATE())

            if key._ownerpassword != None:
                inSensitiveOwner = TPM2B_SENSITIVE_CREATE(
                    TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH(key._ownerpassword)))

            if key._use_ek_cert:
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
                    expiration = -(2)
                    ectx.policy_secret(
                        ESYS_TR.ENDORSEMENT, session, nonce, b"", b"", expiration
                    )
                    ectx.trsess_set_attributes(session, TPMA_SESSION.ENCRYPT | TPMA_SESSION.DECRYPT)
                    return session

                tmpl = ek_rsa2048.template

                primary1, ek_pub, _, _, _ = ectx.create_primary(
                    inSensitiveOwner, tmpl, ESYS_TR.ENDORSEMENT)

                ek_name = ek_pub.get_name()
                sess = setup_ek_session(ectx)
                rkeyLoaded = ectx.load(primary1, key.private, key.public,  session1=sess)
                ectx.flush_context(primary1)
            else:
                primary1, _, _, _, _ = ectx.create_primary(
                    inSensitiveOwner,  TPM2B_PUBLIC(publicArea=self._parent_ecc_template))
                rkeyLoaded = ectx.load(primary1, key.private, key.public)
                ectx.flush_context(primary1)
            
            # if k.empty_auth == False and self._password == '':
            #     raise Exception("key has auth but password not set")

            if key._password != '' and key._password != None:
                ectx.tr_set_auth(rkeyLoaded, key._password)


            tmpl = ek_rsa2048.template

            handle, outpub, _, _, _ = ectx.create_primary(
                inSensitiveOwner, tmpl, ESYS_TR.ENDORSEMENT)

            # n = ectx.tr_get_name(handle)
            n = outpub.get_name()
            if self._enc_key_name != "" and self._enc_key_name != None:
                if bytes(n).hex() != self._enc_key_name:
                    raise Exception("session encryption key name mismatch: expected {}, got {}".format(
                        self._enc_key_name, bytes(n).hex()))       
                         


            digest, ticket = ectx.hash(msg, TPM2_ALG.SHA256, ESYS_TR.ENDORSEMENT)

            if key._policy_impl == None:
                hsess = ectx.start_auth_session(
                    tpm_key=handle,
                    bind=ESYS_TR.NONE,
                    session_type=TPM2_SE.HMAC,
                    symmetric=TPMT_SYM_DEF(
                        algorithm=TPM2_ALG.AES,
                        keyBits=TPMU_SYM_KEY_BITS(sym=128),
                        mode=TPMU_SYM_MODE(sym=TPM2_ALG.CFB),
                    ),
                    auth_hash=TPM2_ALG.SHA256,
                )
                ectx.trsess_set_attributes(
                    hsess, (TPMA_SESSION.DECRYPT)
                )
                s = ectx.sign(rkeyLoaded, TPM2B_DIGEST(
                    digest), scheme, ticket, session1=hsess)
            else:
                sess = key._policy_impl.policy_callback(
                    ectx=ectx, handle=handle)
                s = ectx.sign(rkeyLoaded, TPM2B_DIGEST(digest),
                              scheme, ticket, session1=sess)
                
            ectx.flush_context(handle)
            ectx.flush_context(rkeyLoaded)
            ectx.close()

            match key.key_type():
                case TPM2_ALG.RSA:
                    match scheme.scheme:
                        case TPM2_ALG.RSASSA:    
                            return bytes(s.signature.rsassa.sig)
                        case TPM2_ALG.RSAPSS:
                            return bytes(s.signature.rsapss.sig)
                        case _:
                            raise Exception("unsupported key scheme during sign")                           
                case TPM2_ALG.ECC:
                    rpt = s.signature.ecdsa.signatureR.buffer
                    spt = s.signature.ecdsa.signatureS.buffer               
          
                    return  bytes(rpt) + bytes(spt)

                case _:
                    raise Exception("unsupported key type during sign")
        except Exception as e:
            raise Exception(e)

