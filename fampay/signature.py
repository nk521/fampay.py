import base64
import hashlib

from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS

from fampay.constants import FamAppConstants


class SignatureEngine:
    """Signature engine replicating Fampay x-signature scheme.

    App flow (CryptoHelperImpl + OAuthInterceptor):
      1. message = f"{url}:{sha256(first 64 bytes of body)}:{timestamp}:
                    {APK cert SHA1}:{userAgent}:1:{versionCode}:1", then strip all spaces
      2. sign with SHA256withECDSA (DER encoded) using Android Keystore P-256 key
         (alias "PhamAliaz"), base64 -> x-signature
      3. same timestamp -> X-Timestamp, version -> x-signature-version: 1

    Server verifies x-signature against `public_key` embedded in request body
    ("EVE:" + base64 SPKI of the same key), plus checks app cert SHA1 hash.
    So we generate our own keypair, embed its SPKI, and sign messages with it.

    Flutter side: DioClientsManager.enterstellarClient adds
    x-signature / x-signature-version / X-TIMESTAMP per request through
    FlutterToHostInteraction.generateSignature pigeon channel.
    """

    def __init__(self, private_key: ECC.EccKey | None = None) -> None:
        """App generates EC secp256r1 in Android Keystore (alias "PhamAliaz"). Curve identical here."""
        self.private_key = private_key if private_key is not None else self.generate_keypair()

    @classmethod
    def generate_keypair(cls) -> ECC.EccKey:
        """App generates EC secp256r1 in Android Keystore. Curve identical here."""
        return ECC.generate(curve="P-256")

    @property
    def public_key(self) -> ECC.EccKey:
        return self.private_key.public_key()

    @property
    def public_key_spki_b64(self) -> str:
        """Base64 of SPKI DER. In app this comes from CryptoHelperImpl.k():
        keystore Certificate.getPublicKey().getEncoded() (X.509/SPKI) -> base64.
        The body value is prefixed 'EVE:' (PublicKeySignalReader algorithm tag)."""
        return base64.b64encode(self.public_key.export_key(format="DER")).decode()

    @staticmethod
    def body_hash(body: bytes) -> str:
        """OAuthInterceptor: body written to okio Buffer, first 64 bytes COPIED to a
        probe buffer to scan for control chars (refuse signing binary bodies).
        Actual signed hash = SHA-256 hex over the FULL body as string. Multipart
        or empty bodies hash the empty string instead.
        """
        try:
            text = body.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            text = ""
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @staticmethod
    def build_message(url: str, body: bytes, timestamp: str, user_agent: str, version_code: str) -> str:
        """CryptoHelperImpl$signPayload$1$signature$1: exact concat, then strip spaces."""
        msg = ":".join(
            [
                url,
                SignatureEngine.body_hash(body),
                timestamp,
                SignatureEngine._cert_sha1_colonized(),
                user_agent,
                FamAppConstants.SIGNATURE_VERSION,
                version_code,
                "1",
            ],
        )
        return msg.replace(" ", "")

    def sign_message(self, message: str) -> str:
        """SHA256withECDSA, DER-encoded (matches java.security.Signature output),
        Base64 NO_WRAP -> x-signature value."""
        digest = SHA256.new(message.encode("utf-8"))
        signer = DSS.new(self.private_key, "fips-186-3", encoding="der")
        return base64.b64encode(signer.sign(digest)).decode()

    def verify_message(self, message: str, signature_b64: str) -> bool:
        """Server-side equivalent. Useful to self-test before firing the request."""
        digest = SHA256.new(message.encode("utf-8"))
        verifier = DSS.new(self.public_key, "fips-186-3", encoding="der")
        try:
            verifier.verify(digest, base64.b64decode(signature_b64))
            return True
        except ValueError:
            return False

    @staticmethod
    def _cert_sha1_colonized() -> str:
        """AppIntegrityCheckHelper formats digest as colon-separated hex, uppercase.
        The ' ' strip in build_message does NOT remove colons, so keep them."""
        hexed = FamAppConstants.APP_CERT_SHA1.lower()
        return ":".join(hexed[i : i + 2] for i in range(0, len(hexed), 2)).upper()
