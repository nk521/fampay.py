from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class _FamAppApiStore:
    BASE = "https://hogwarts.famapp.in/"

    # Session managements (this part is implemented in dart)
    SESSION_MANAGEMENT_BASE = BASE + "enterstellar/"
    SESSION_LOGIN = SESSION_MANAGEMENT_BASE + "api/v1/login/session/"
    SESSION_SIM_BINDING_VERIFY = SESSION_MANAGEMENT_BASE + "api/v1/login/sim-binding/verify/"
    SESSION_GENERATE_TOKEN = SESSION_MANAGEMENT_BASE + "api/v1/login/generate-token/"


@dataclass(frozen=True, slots=True)
class FamAppConstants:
    APP_VERSION_CODE = "2602003"  # FamBase.t
    APP_VERSION_NAME = "26.2.3"  # FamBase.u
    PLATFORM = "1"  # Android

    # SHA-1 over the APK signing certificate DER (extracted from
    # META-INF/BNDLTOOL.RSA of 26.2.3). Server pins this value.
    APP_CERT_SHA1 = "43A2BD6824215BE3454B203BE7EC9E5A926BDDE7"
    SIGNATURE_VERSION = "1"

    api = _FamAppApiStore()
