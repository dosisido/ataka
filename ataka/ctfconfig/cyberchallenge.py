import json
from datetime import datetime
from ataka.common.flag_status import FlagStatus
import requests
from collections import defaultdict

### EXPORTED CONFIG

CC_TEAM_ID = "6"
CC_NOP_TEAM_ID = "0"
CC_GAME_SERVER_IP = '10.10.0.1'
CC_TEAM_TOKEN = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

# Ataka Host Domain / IP
ATAKA_HOST = '10.91.142.1:8000'

# Default targets for atk runlocal
RUNLOCAL_TARGETS = [f"10.60.{CC_NOP_TEAM_ID}.1"]

# IPs that are always excluded from attacks.
STATIC_EXCLUSIONS = {f'10.60.{CC_TEAM_ID}.1', f'10.60.{CC_NOP_TEAM_ID}.1'}

ROUND_TIME = 120

# format: regex, group where group 0 means the whole regex
FLAG_REGEX = r"[A-Z0-9]{31}=", 0

FLAG_BATCHSIZE = 69

FLAG_RATELIMIT = 1  # Wait in seconds between each call of submit_flags()

# When the CTF starts
START_TIME = int(datetime.fromisoformat("2024-06-15T10:11:11+02:00").timestamp())


### END EXPORTED CONFIG

valid_flags = set()
services: list[str] = []

def parse_flag(flag: str) -> tuple[int, int, int]:
    round_number = int(flag[0:2], 36)
    team_number = int(flag[2:4], 36)
    service_number = int(flag[4:6], 36)
    return (round_number, team_number, service_number)

def get_targets():
    global services

    r = requests.get(f"http://{CC_GAME_SERVER_IP}:8081/flagIds", timeout=10)
    data = r.json()
    if not services:
        services = list(data.keys())
        print(f"Services: {services}")

    targets = defaultdict(list)

    for service_number, service in enumerate(services):
        for team_id, info in data[service].items():
            for tick, flagId in info.items():
                if (int(tick), int(team_id), int(service_number)) in valid_flags: continue
                targets[service].append({
                    "ip": f"10.60.{team_id}.1",
                    "extra": json.dumps(flagId),
                })

    return dict(targets)


def parse_submission(sub: str) -> FlagStatus:
    status = sub["status"]
    msg = sub["msg"].lower()

    if status == "ACCEPTED":
        return FlagStatus.OK

    if status == "RESUBMIT":
        # not active yet
        return FlagStatus.QUEUED

    if status == "ERROR":
        return FlagStatus.ERROR

    # status == "DENIED"
    if "invalid flag" in msg:
        return FlagStatus.INVALID
    if "nop team" in msg:
        return FlagStatus.NOP
    if "your own" in msg:
        return FlagStatus.OWNFLAG
    if "too old" in msg:
        return FlagStatus.INACTIVE
    if "already claimed" in msg:
        # we already submitted and got told so
        return FlagStatus.DUPLICATE
    if "didn't terminate successfully" in msg:
        # treat dispatch‐failure as an error
        return FlagStatus.ERROR

    # fallback
    return FlagStatus.UNKNOWN

def submit_flags(_flags):
    flags = {flag: i for i, flag in enumerate(_flags)}

    data = requests.put(f'http://{CC_GAME_SERVER_IP}:8080/flags', headers={
        'X-Team-Token': CC_TEAM_TOKEN
    }, json=_flags).json()

    result = [FlagStatus.ERROR]*len(flags)
    for flag_response in data:
        flag = flag_response['flag']
        status = parse_submission(flag_response)
        result[flags[flag]] = status
        if status == FlagStatus.OK:
            valid_flags.add(parse_flag(flag))
    return result
