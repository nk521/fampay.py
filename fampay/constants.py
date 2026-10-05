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
class FamAppConsts:
    VERSION_CODE = "2602003"
    api = _FamAppApiStore()
