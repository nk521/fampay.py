import hashlib
import re
import subprocess
from dataclasses import dataclass


@dataclass
class AndroidPhone:
    """
    NOTE: from_adb requires adb to be running as root.
    """

    manufacturer: str = ""
    model: str = ""
    device: str = ""
    os_release: str = ""
    android_id: str = ""
    sim_slot: int = 0
    subscription_id: int = -1
    icc_id: str = ""
    phone_number: str = ""
    profile_name: str = ""
    sim_carrier: str = ""

    @staticmethod
    def _adb(*args: str) -> str:
        out = subprocess.run(["adb", "shell", *args], capture_output=True, text=True)
        return out.stdout.strip()

    @classmethod
    def from_adb(cls, phone_number: str, sim_slot: int = 0) -> AndroidPhone:
        p = cls()
        p.manufacturer = p._adb("getprop", "ro.product.manufacturer")
        p.model = p._adb("getprop", "ro.product.model")
        p.device = p._adb("getprop", "ro.product.device")
        p.os_release = p._adb("getprop", "ro.build.version.release")
        p.android_id = p._adb("settings", "get", "secure", "android_id")
        p.profile_name = ""
        p.phone_number = phone_number

        # SIM info: _id=subscription_id, sim_id=slot index, icc_id
        # adb shell content query --uri content://telephony/siminfo
        rows = p._adb("content", "query", "--uri", "content://telephony/siminfo", "--projection", "_id,sim_id,icc_id")
        for row in rows.splitlines():
            m = re.search(r"_id=(\d+).*sim_id=(-?\d+).*icc_id=([^,\s]+)", row)
            if m and int(m.group(2)) == sim_slot:
                p.subscription_id = int(m.group(1))
                p.sim_slot = sim_slot
                p.icc_id = m.group(3)
                break
        else:  # fallback for single-SIM devices where sim_id may be absent
            m = re.search(r"_id=(\d+)", rows or "")
            if m:
                p.subscription_id, p.sim_slot = int(m.group(1)), 0

        return p

    @property
    def fampay_device_id(self) -> str:
        """DeviceIdFactory.b: SHA1(android_id) as UPPERCASE hex ('-1' if empty)."""
        aid = self.android_id
        if not aid:
            return "-1"
        return hashlib.sha1(aid.encode()).hexdigest().upper()

    @property
    def fampay_user_agent(self) -> str:
        """BaseRepository.b(): model | Android X | VM/ver | device | deviceId | ver (Build code) | profile"""
        return (
            f"{self.model} | Android {self.os_release} | Dalvik/2.1.0 | {self.device} | "
            f"{self.fampay_device_id} | 26.2.3 (Build 2602003) | "
            f"{self.profile_name}"
        )
