import json
import logging
import os
import subprocess
import time
import xml.etree.ElementTree as ET
from urllib.request import Request, urlopen

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s %(asctime)s %(message)s",
    datefmt="%H:%M:%S",
)

OPENWRT_SSH_USER = "root"
OPENWRT_ROOT_PASS = ""
OPENWRT_IP = "192.168.10.110"

HISENSE_TV_IP = "192.168.10.182"
LG_TV_IP = "192.168.10.252"

HASS_URL = "http://192.168.10.129:8123"
ACCESS_TOKEN = ""
LG_TV_ENTITY_ID = "media_player.lg_webos_tv_75uq9000psd"


DURATION_SECONDS = 60 * 60
CHECK_INTERVAL_SECONDS = 60

LG_STATES = {"on", "idle"}

TVS = {
    "Hisense": {
        "ip": HISENSE_TV_IP,
        "check": "nmap",
        "rule": "block_hisense_tv",
        "rule_name": "Block Hisense TV Internet",
    },
    "LG": {
        "ip": LG_TV_IP,
        "entity_id": LG_TV_ENTITY_ID,
        "check": "home_assistant",
        "rule": "block_lg_tv",
        "rule_name": "Block LG TV Internet",
    },
}


def nmap_is_online(ip):
    result = subprocess.run(
        ["nmap", "-sn", "-oX", "-", ip],
        capture_output=True,
        text=True,
        timeout=20,
        check=True,
    )

    root = ET.fromstring(result.stdout)
    return any(
        host.find("status") is not None
        and host.find("status").get("state") == "up"
        for host in root.findall("host")
    )


def get_home_assistant_state(entity_id):
    if not ACCESS_TOKEN:
        raise ValueError("Set ACCESS_TOKEN to your Home Assistant access token.")

    url = f"{HASS_URL.rstrip('/')}/api/states/{entity_id}"
    request = Request(
        url,
        headers={
            "Authorization": f"Bearer {ACCESS_TOKEN}",
            "Content-Type": "application/json",
        },
    )

    with urlopen(request, timeout=10) as response:
        data = json.loads(response.read().decode("utf-8"))

    return data["state"].lower()


def tv_is_online(name, tv):
    if tv["check"] == "home_assistant":
        state = get_home_assistant_state(tv["entity_id"])
        logging.info("%s Home Assistant tv state: %s", name, state)
        return state in LG_STATES

    return nmap_is_online(tv["ip"])


def make_enable_command(tv):
    rule = tv["rule"]
    ip = tv["ip"]
    name = tv["rule_name"]

    return (
        f"uci set firewall.{rule}=rule; "
        f"uci set firewall.{rule}.name='{name}'; "
        f"uci set firewall.{rule}.src='lan'; "
        f"uci set firewall.{rule}.src_ip='{ip}'; "
        f"uci set firewall.{rule}.dest='wan'; "
        f"uci set firewall.{rule}.target='REJECT'; "
        f"uci set firewall.{rule}.proto='all'; "
        f"uci set firewall.{rule}.enabled='1'; "
        f"uci set firewall.{rule}.family='ipv4'; "
        "uci commit firewall; "
        "/etc/init.d/firewall restart"
    )


def make_disable_command(tv):
    rule = tv["rule"]
    return (
        f"uci delete firewall.{rule} 2>/dev/null; "
        "uci commit firewall; "
        "/etc/init.d/firewall restart"
    )


def run_router_command(remote_command):
    env = os.environ.copy()
    env["SSHPASS"] = OPENWRT_ROOT_PASS

    command = [
        "sshpass",
        "-e",
        "ssh",
        "-o", "PreferredAuthentications=password,keyboard-interactive",
        "-o", "PubkeyAuthentication=no",
        "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=accept-new",
        f"{OPENWRT_SSH_USER}@{OPENWRT_IP}",
        remote_command,
    ]

    subprocess.run(
        command,
        check=True,
        timeout=30,
        env=env,
        capture_output=True,
        text=True,
    )


def main():
    states = {
        name: {
            "condition": None,
            "condition_since": None,
            "last_action": None,
        }
        for name in TVS
    }

    logging.info("Monitoring Hisense with Nmap and LG through Home Assistant.")

    while True:
        for name, tv in TVS.items():
            try:
                online = tv_is_online(name, tv)
            except (subprocess.SubprocessError, ET.ParseError, OSError,
                    ValueError, KeyError) as error:
                logging.info(
                    "%s status check failed; keeping its timer: %s",
                    name,
                    error,
                )
                continue

            state = states[name]
            now = time.monotonic()
            condition = "online" if online else "offline"

            if condition != state["condition"]:
                state["condition"] = condition
                state["condition_since"] = now
                logging.info("%s is %s. Starting its timer.", name, condition)

            elapsed = now - state["condition_since"]
            logging.info(
                "%s is %s for %d seconds.",
                name,
                condition,
                int(elapsed),
            )

            if elapsed >= DURATION_SECONDS:
                if condition == "online" and state["last_action"] != "enabled":
                    logging.info(
                        "%s has been online long enough. Enabling its firewall rule.",
                        name,
                    )
                    try:
                        run_router_command(make_enable_command(tv))
                        state["last_action"] = "enabled"
                        logging.info("%s firewall rule enabled.", name)
                    except subprocess.SubprocessError as error:
                        logging.info(
                            "Could not enable %s rule; will retry: %s",
                            name,
                            error,
                        )

                elif condition == "offline" and state["last_action"] != "disabled":
                    logging.info(
                        "%s has been offline long enough. Removing its firewall rule.",
                        name,
                    )
                    try:
                        run_router_command(make_disable_command(tv))
                        state["last_action"] = "disabled"
                        logging.info("%s firewall rule removed.", name)
                    except subprocess.SubprocessError as error:
                        logging.info(
                            "Could not remove %s rule; will retry: %s",
                            name,
                            error,
                        )

        time.sleep(CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
