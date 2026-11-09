# PyJWT TPM provider

Python library to create JWT tokens using [PyJWT](https://pyjwt.readthedocs.io/en/stable/) where the private key is on a TPM.

You can use this to issue a JWT in the following alg:

* `RS256`
* `PS256`
* `ES256`

The TPM key can be bound using Password or arbitrary TPM Auth policies.  For example, you can bind use of the key to a password or to a PCR policy

on python pypi: https://pypi.org/project/pyjwt-tpm/

---

## Usage

```python
from pyjwt_tpm import TPMSigner, SigningAlgorithm, TPMKey
import jwt

## initialize a signer and a key
tpm_signer = TPMSigner(tcti='device:/dev/tpmrm0', algorithm=SigningAlgorithm.RS256)
tpm_key = TPMKey(keyfile='keys/rsa_key.pem)

jws_instance = jwt.PyJWS()
jws_instance.unregister_algorithm("RS256")
jws_instance.register_algorithm("RS256", tpm_signer)

jwt_instance = jwt.PyJWT()
jwt_instance._jws = jws_instance 

### create JWT
payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
token = jwt_instance.encode(
    payload, 
    key=tpm_key, 
    algorithm="RS256"
)
print(token)

### print public PEM key
public_key = tpm_key.public_pem()
print(public_key)

### verify
### note, you can validate with just the RSA Public key
decoded_payload = jwt.decode(
    token,
    public_key,
    algorithms=["RS256"]
)
```

## QuickStart


You can use a software TPM ([swtpm](https://github.com/stefanberger/swtpm)) if you just want to test, if you want to use a real tpm, skip this step 

```bash
cd example/
# rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm && swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --ecc  --create-ek-cert && 
swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=5

## in a new window
pip3 install -r requirements.txt

export TPM2TOOLS_TCTI="swtpm:port=2321"
export TPM2OPENSSL_TCTI="swtpm:port=2321"

## test rsassa
python3 main_rs.py

### test rsassa
python3 main_ps.py

### test ecc
python3 main_es.py
```



## Keys

This library uses [PEM formatted TPM keys](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html) which is a common format supported in [openssl](https://github.com/tpm2-software/tpm2-openssl) and [tpm2_tools](https://github.com/tpm2-software/tpm2-tools).


A sample TPM PEM key would look like

```
-----BEGIN TSS2 PRIVATE KEY-----
MIICFAYGZ4EFCgEDoAMBAQECBEAAAAEEggEaARgAAQALAAQAcgAAABAAFAALCAAA
AAAAAQDEIIOkNNJzPIq9NNYzqE7zpjR7RuNBjKup61+6WgTGpSo3Rn5siyPAgOB6
jI81peMs/jaqKENAE85LHS1fST9/AEHaSqmoP/sIT5LPwtK5w8MdAaBDSZEocw8a
kHCms4/v3cx5K9tOZuM+kIMpurgZzyH5AE1yiHjzU3/okPzIIhmAny17KZXJcb8T
LGdebG9N5QkTXVvcBVy7VtYMHDDWxoBohFeo9bfOMV9bmypesCdPdayTY6nnv2c+
IURFx41OIjw4zRj0kgtGI5TuSqL32jkiM9BPsNJVV0uJvf/aCCwCAs8oiybYSM+n
NbOTDyiR3+w9AUh7QLkbwQzgHxxNBIHgAN4AIPWKPFKnKD4ZYBPJ2JN7HSQWeBRy
HQXmikTuzIK1N7SRABBuR20se27auk2VcTxeve/8rme1ePGWoxHnBhzlAA6gwkYv
CpBQJGZETZaxQi7Sn+IgTaXswjrqU4QclxxWVusw7OZENyK9HTFyXsPMDNQDnf+3
kuK4X/pBqOgHhKSQLKpk2d4gEw7WqHx8JUq2eqK//TmegBfZK20i7Ew8y6M2M/Nq
UbkiGJVMxHiq2tLQbep7F4/ank24ZX99iPtc2XJ1sEELzXp2pev5nHSJLr04oEMv
hgVVXIL4C70=
-----END TSS2 PRIVATE KEY-----
```

You can create a TPM based key in a number of ways:

* with `tpm2_tools`

```bash
export TPM2TOOLS_TCTI="swtpm:port=2321" 

## create an H2 Primary
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256 \
    -c primary.ctx \
    -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2_create -G rsa2048:rsassa:null -g sha256 -u rsa_key.pub -r rsa_key.priv -C primary.ctx
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
tpm2_load -C primary.ctx -u  rsa_key.pub -r  rsa_key.priv -c  rsa_key.ctx 
tpm2_encodeobject -C primary.ctx -u rsa_key.pub -r rsa_key.priv -o rsa_key.pem

tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
```

* with `openssl`

```bash
export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules/
export TPM2OPENSSL_TCTI="swtpm:port=2321"

openssl genpkey -provider tpm2 -provider default -algorithm rsa -pkeyopt rsa_keygen_bits:2048  -pkeyopt rsa_keygen_pubexp:65537  -out rsa_key_openssl.pem

## rsa-pss
# openssl genpkey -provider tpm2 -provider default -algorithm rsa-pss  -pkeyopt rsa_pss_keygen_md:sha256   -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out rsa_key_pss_openssl.pem
## ecc
# openssl genpkey -provider tpm2 -provider default -algorithm ec -pkeyopt  ec_paramgen_curve:P-256 -pkeyopt digest:sha256  -out ec_key_openssl.pem
# openssl rsa -provider tpm2 -provider default -in rsa_key_openssl.pem -text
```

* with [tpm2genkey](https://github.com/salrashid123/tpm2genkey)

```bash
wget https://github.com/salrashid123/tpm2genkey/releases/download/v0.8.5/tpm2genkey_0.8.6_linux_amd64
./tpm2genkey --mode=create --alg=rsa --rsascheme=rsassa --out=rsassa.pem -tpm-path="127.0.0.1:2321"
./tpm2genkey --mode=create --alg=rsa --rsascheme=rsapss --out=rsapss.pem -tpm-path="127.0.0.1:2321"
./tpm2genkey --mode=create --alg=ecdsa --out=ec.pem -tpm-path="127.0.0.1:2321"
```


```bash
export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules/
export TPM2OPENSSL_TCTI="swtpm:port=2321"

openssl genpkey -provider tpm2 -provider default -algorithm rsa -pkeyopt rsa_keygen_bits:2048  -pkeyopt rsa_keygen_pubexp:65537  -out rsa_key_openssl.pem
openssl genpkey -provider tpm2 -provider default -algorithm rsa-pss  -pkeyopt rsa_pss_keygen_md:sha256   -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out rsa_key_pss_openssl.pem
openssl genpkey -provider tpm2 -provider default -algorithm ec -pkeyopt  ec_paramgen_curve:P-256 -pkeyopt digest:sha256  -out ec_key_openssl.pem
openssl rsa -provider tpm2 -provider default -in rsa_key_openssl.pem -text
```

- RSASSA Key

```bash
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256 \
    -c primary.ctx \
    -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2_create -G rsa2048:rsassa:null -g sha256 -u rsa_key.pub -r rsa_key.priv -C primary.ctx
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
tpm2_load -C primary.ctx -u  rsa_key.pub -r  rsa_key.priv -c  rsa_key.ctx 
tpm2_encodeobject -C primary.ctx -u rsa_key.pub -r rsa_key.priv -o rsa_key.pem
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
```

- RSAPSS Key

To create a 

```bash
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256 \
    -c primary.ctx \
    -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2_create -G rsa2048:rsapss:null -g sha256 -u rsa_key_pss.pub -r rsa_key_pss.priv -C primary.ctx
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
tpm2_load -C primary.ctx -u  rsa_key_pss.pub -r  rsa_key_pss.priv -c  rsa_key_pss.ctx 
tpm2_encodeobject -C primary.ctx -u rsa_key_pss.pub -r rsa_key_pss.priv -o rsa_key_pss.pem
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
```

- ECC Key

```bash
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256 \
    -c primary.ctx \
    -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2_create -G ecc:ecdsa -g sha256 -u ecc_key.pub -r ecc_key.priv -C primary.ctx
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
tpm2_load -C primary.ctx -u  ecc_key.pub -r  ecc_key.priv -c  ecc_key.ctx 
tpm2_encodeobject -C primary.ctx -u ecc_key.pub -r ecc_key.priv -o ecc_key.pem
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
```


## Policies

The key can be bound to certain polcies too.  


### Password Auth

If you want to provide a passphrase to use the TPM based key, you can setup userAuth based access.


```bash
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256 \
    -c primary.ctx \
    -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat
tpm2_create -G rsa2048:rsassa:null -g sha256 -u rsa_key_password.pub -r rsa_key_password.priv -C primary.ctx -p foo
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
tpm2_load -C primary.ctx -u  rsa_key_password.pub -r  rsa_key_password.priv -c  rsa_key_password.ctx 
tpm2_encodeobject -C primary.ctx -u rsa_key_password.pub -r rsa_key_password.priv -o rsa_key_password.pem -p
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l


```

### PCR Policy

To create a key with a PCR policy (i.,e a policy which enforces the key can only be used if certain PCR values exist)

```bash
export PCR=23
export HASH=sha256
export PCRBANK=$HASH:$PCR

$ tpm2_pcrread sha256:23
  sha256:
    23: 0x0000000000000000000000000000000000000000000000000000000000000000

tpm2_pcrextend 23:sha256=0x0000000000000000000000000000000000000000000000000000000000000000

$ tpm2_pcrread sha256:23
  sha256:
    23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256 \
    -c primary.ctx \
    -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2_startauthsession -S session.dat
tpm2_pcrread "$PCRBANK" -o pcr23_val.bin
tpm2_policypcr -S session.dat -l "$PCRBANK"  -L policy.dat -f pcr23_val.bin
tpm2_flushcontext session.dat
tpm2_create -G rsa2048:rsassa:null -g sha256 -u rsa_key_pcr.pub -r rsa_key_pcr.priv -C primary.ctx -L policy.dat
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
tpm2_load -C primary.ctx -u rsa_key_pcr.pub -r rsa_key_pcr.priv -c rsa_key_pcr.ctx 
tpm2_encodeobject -C primary.ctx -u rsa_key_pcr.pub -r rsa_key_pcr.priv -o rsa_key_pcr.pem -p
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
```

### PolicyAuthValue and PolicyDuplicateSelect

If you remotely transferred the key using [tpmcopy](https://github.com/salrashid123/tpmcopy/tree/main?tab=readme-ov-file#rsa), you will need to fulfill `PolicyAuthValue` and `PolicyDuplicateSelect`.

From there, you can instantiate `PolicyORAndDuplicateSelectPolicy` as shown in `example/main_policy_duplicate.py`


```bash
wget https://github.com/salrashid123/tpmcopy/releases/download/v0.5.2/tpmcopy_0.5.2_linux_amd64
export TPMB="127.0.0.1:2321"

./tpmcopy_0.5.2_linux_amd64 --mode publickey --parentKeyType=rsa_ek -tpmPublicKeyFile=ek_public.pem --tpm-path=$TPMB
openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out rsakey.pem

openssl pkcs8 -topk8 -nocrypt -in rsakey.pem  -out rsakey-pkcs8.pem

./tpmcopy_0.5.2_linux_amd64  --mode duplicate --keyType=rsa --secret=rsakey-pkcs8.pem --rsaScheme=rsassa \
 --hashScheme=sha256  -tpmPublicKeyFile=ek_public.pem -out=out.json

./tpmcopy_0.5.2_linux_amd64 --mode import --parentKeyType=rsa_ek --in=out.json --out=rsa_key_dupliate.pem  --tpm-path=$TPMB


python3 main_policy_duplicate.py
```

#### Custom Policy Implementation

The built repo contains a helper function which fulfills a `PCR` policy (i.,e certain PCR values must be present to use the key).

You can define your own class which fulfills any number of supported polcies as described in [TCG TSS 2.0 JSON Data Types and Policy LanguageSpecification](https://trustedcomputinggroup.org/wp-content/uploads/TSS_JSON_Policy_v0.7_r04_pubrev.pdf)


The way to do this is to implement an abstract class:

```python
from cloud_auth_tpm.policy.policy import PolicyEval
```

which requires you to pass in a policy json on init and then impelment whatever you need to do in `policy_callback(ectx: ESAPI, handle: ESYS_TR):`, eg:


```python
class PolicyEval(object, metaclass=ABCMeta):
    def __init__(self, policy: dict[str, any] , debug: bool):

    @abstractmethod
    def policy_callback(self, ectx: ESAPI, handle: ESYS_TR):
        pass
```

where `ectx` is just the TPM context and `handle` is what key used for session encryption.


## Session Encryption

Each operation uses [encrypted sessions](https://trustedcomputinggroup.org/wp-content/uploads/TCG_CPU_TPM_Bus_Protection_Guidance_Passive_Attack_Mitigation_8May23-3.pdf) by default and interrogates the TPM for the current EK directly.

If for whatever reason you want to specify the "name" of the EK to to use, set the `--tpm-session-encrypt-with-name=` parameter shown below

```bash

$ tpm2_createek -c /tmp/primaryB.ctx -G rsa  -Q
tpm2_readpublic -c /tmp/primaryB.ctx -o /tmp/ekpubB.pem -n /tmp/ekpubBname.bin -f PEM -Q
xxd -p -c 100 /tmp/ekpubBname.bin 
000bfcfb59368b19aae7d961247d56ad0f5264ef284e8339b590c3f34b99ce18aba2


# Then use the hex value returned in the --tpm-session-encrypt-with-name= argument.
   --tpm-session-encrypt-with-name=000bfcfb59368b19aae7d961247d56ad0f5264ef284e8339b590c3f34b99ce18aba2
```


#### Testing and Installation

To test


```bash
pytest testing/test_all.py  -p no:warnings
```


then to install

```bash
pip3 install setuptools
python3 setup.py sdist bdist_wheel

cd example
virtualenv env
source env/bin/activate

pip3 install ../
```







