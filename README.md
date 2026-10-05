Notes:
---

This project serves as a baseline for how I think a minimal TPAP API client should look: something without ads and other distractions.

I might port it to a generic client with multiple backends, which is something I set out to do in librefin, but there were some complications back then.

Fampay seems to be a stable choice compared to other TPAPs because they don't change stuff a lot, and the app is pretty easy to snoop into and take apart. If another researcher is taking Fampay's app apart, here are a few small pointers:

I made a Swagger spec available for some API groups that Fampay uses: https://oa-specs.nkmason.dev/. These live on the native side. The auth endpoints live on the dart side, and the backend keeps track of Android device IDs and whether they're rooted or not. This is taken up by the "potter" service. You cannot hook into the app and change things because Pairip will block you. Rather, spoof calls to potter. The app makes a call to Firebase for config, and that will give you the potter service's public key. It then makes 120 checks, some of which check root and some of which check integrity. You can send the potter assessment yourself to maybe lie to the backend and whitelist your device.

```python
import base64
import gzip
import json
import os

import requests
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA

DIGEST_URL = "https://hogwarts.famapp.in/potter/v1/digest"

# Firebase Remote Config "potter_pk"
POTTER_PK_DEFAULT = """-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEApnVZNI/3bHUnYtwvX/bi
XCsi1MvsEp+jMh..................................................
................................................................
................................................................
................................................................
................................................................
................................................................
.............................................s9nJNpHuc6nwgFCPDD1
e/tsRZjLY3/FJG7SpFM20IP+e4qIaSpHJSw4QpKPkNHdAgMBAAE=
-----END PUBLIC KEY-----"""

ALL_CHECK_IDS = list(range(1, 120))

# Known root check ids
ROOT_CHECK_IDS = {1, 2, 3, 4, 7, 10, 11, 12, 13, 14, 29}

# kill-switch checks (integrity_kill_checks default config)
KILL_CHECK_IDS = {87, 91, 92}


def _encrypt(checks: dict, rsa_pub_pem: str = POTTER_PK_DEFAULT) -> dict[str, str]:
    pub = RSA.import_key(rsa_pub_pem)
    blob = gzip.compress(json.dumps(checks, separators=(",", ":")).encode())
    aes_key = os.urandom(32)
    nonce = os.urandom(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce, mac_len=16)
    ct, tag = cipher.encrypt_and_digest(blob)
    # Java Cipher.doFinal(AES/GCM/NoPadding) output = ciphertext || tag
    ek = PKCS1_OAEP.new(pub, hashAlgo=SHA256).encrypt(aes_key)
    return {
        "data": base64.b64encode(ct + tag).decode(),
        "ek": base64.b64encode(ek).decode(),
        "n": base64.b64encode(nonce).decode(),
    }

def forge_report(
    device_id_hashed: str,
    *,
    flagged_ids: set[int] | None = None,
    check_ids: list[int] | None = None,
    rsa_pub_pem: str = POTTER_PK_DEFAULT,
    extra_values: dict[int, int] | None = None,
) -> dict:
    """Build a full EncryptedPayload body for POST potter/v1/digest.

    device_id_hashed : the SHA1(android_id); look at fampay.phone.AndroidPhone::fampay_device_id()
    flagged_ids      : check ids to report as 1 (detected). Default {} = all clean
    check_ids        : which ids to include (default ALL_CHECK_IDS, matches app shape)
    extra_values     : override specific values (e.g. {6: "<android_id string>"})
                       — check 6 carries android_id as its value, non-bool
    """
    flagged = flagged_ids or set()
    ids = check_ids or ALL_CHECK_IDS
    values = {str(i): (1 if i in flagged else 0) for i in ids}
    if extra_values:
        for i, v in extra_values.items():
            values[str(i)] = v
    payload = _encrypt(values, rsa_pub_pem)
    payload["device_id"] = device_id_hashed
    return payload

def send_report(body: dict, headers: dict, timeout: float = 20.0) -> requests.Response:
    """POST to potter/v1/digest with given headers (must include at minimum
    User-Agent matching device persona)."""
    return requests.post(
        DIGEST_URL,
        json=body,
        headers=headers | {"Content-Type": "application/json; charset=UTF-8"},
        timeout=timeout,
    )

def build_headers(
    raw_android_id: str,
    model: str,
    device: str,
    os_release: str,
    version_code: str,
    version_name: str,
    profile_name: str = "",
    authorization: str | None = None,
) -> dict:
    """Replicates the header set from captured potter request.
    Note Device-Id header carries RAW android_id (not hashed)."""
    ua = (f"{model} | Android {os_release} | Dalvik/2.1.0 | {device} | "
          f"{raw_android_id} | {version_name} (Build {version_code}) | "
          f"{profile_name}")
    h = {
        "User-Agent": ua,
        "X-Device-Details": ua,
        "X-App-Version": version_code,
        "X-Platform": "1",
        "Device-Id": raw_android_id,
        "X-Device-Os-Version": os_release,
        "Accept-Etag": "true",
    }
    if authorization:
        h["Authorization"] = authorization
    return h

body = forge_report(
    "0" * 40,  # placeholder device_id — put real SHA1(android_id).upper()
    extra_values={6: "f4a2c9e1d0b34567"},  # check 6 = android_id string
    # flagged_ids=set(),           # default clean
)

h = build_headers(
    raw_android_id="f4a2c9e1d0b34567",
    model="SM-A515F",
    device="a51",
    os_release="16",
    version_code="2604004",
    version_name="26.4.4",
    profile_name="N0I89ZK18O",
    # authorization="Token <jwe>",
)

r = send_report(body, h)

```
