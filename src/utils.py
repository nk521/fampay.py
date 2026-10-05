from src.constants import FamAppConstants
from src.phone import AndroidPhone


def common_headers(phone: AndroidPhone) -> dict[str, str]:
    ua = phone.fampay_user_agent
    return {
        "X-APP-VERSION": FamAppConstants.APP_VERSION_CODE,
        "X-PLATFORM": FamAppConstants.PLATFORM,
        "X-DEVICE-OS-VERSION": phone.os_release,
        "X-DEVICE-MODEL": phone.model,
        "DEVICE-ID": phone.fampay_device_id,
        "User-Agent": ua,
        "X-DEVICE-DETAILS": ua,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
