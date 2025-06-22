import json
from datetime import datetime
from ataka.common.flag_status import FlagStatus
import requests
from collections import defaultdict, namedtuple

### EXPORTED CONFIG

CC_TEAM_ID = "6"
CC_NOP_TEAM_ID = "0"
CC_GAME_SERVER_IP = '10.10.0.1'
CC_TEAM_TOKEN = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

CC_SUBMIT_ENDPOINT = f'http://{CC_GAME_SERVER_IP}:8080/flags'
CC_FLAGIDS_ENDPOINT = f'http://{CC_GAME_SERVER_IP}:8081/flagIds'
CC_SERVICES_ENDPOINT = f'http://{CC_GAME_SERVER_IP}:8081/'
# Ataka Host Domain / IP
ATAKA_HOST = '10.91.142.1:8000'

# Default targets for atk runlocal
RUNLOCAL_TARGETS = [f"10.60.{CC_NOP_TEAM_ID}.1"]

# IPs that are always excluded from attacks.
STATIC_EXCLUSIONS = {f'10.60.{CC_TEAM_ID}.1'}

ROUND_TIME = 120

# format: regex, group where group 0 means the whole regex
FLAG_REGEX = r"[A-Z0-9]{31}=", 0

FLAG_BATCHSIZE = 69

FLAG_RATELIMIT = 2  # Wait in seconds between each call of submit_flags()

# When the CTF starts
START_TIME = int(datetime.fromisoformat("2024-06-15T10:11:11+02:00").timestamp())

# Each how many ticks should clear the valid flags
CLEAR_RATE = 20
CLEAR_LAST_N_TICKS = 10

FlagSubmission = namedtuple("FlagSubmission", ["msg", "flag", "status"])
get_cur_tick = lambda: int(datetime.now().timestamp() - START_TIME) // ROUND_TIME

### END EXPORTED CONFIG

valid_flags = set()
services: list[str] = []

def clear_valid_flags():
    global valid_flags
    cur_tick = get_cur_tick()
    valid_flags = {
        (tick, team_id, service_number) for tick, team_id, service_number in valid_flags
                   if tick >= cur_tick - CLEAR_LAST_N_TICKS
    }


def parse_flag(flag: str) -> tuple[int, int, int]:
    round_number = int(flag[0:2], 36)
    team_number = int(flag[2:4], 36)
    service_number = int(flag[4:6], 36)
    return (round_number, team_number, service_number)

def get_targets():
    global services

    r = requests.get(CC_FLAGIDS_ENDPOINT, timeout=5)
    data = r.json()
    if not services:
        s = requests.get(CC_SERVICES_ENDPOINT, timeout=1).json().get('services', [])
        tmp = []
        for i in s:
            tmp.append(i['id'])
        services = tmp
        print(f"Services: {services}")
        
    targets = defaultdict(list)
    if not data: # rete chiusa
        for s in services:
            targets[s] = []

        return dict(targets)

    for service_number, service in enumerate(services):
        for team_id, info in data[service].items():
            for tick, flagId in info.items():
                if (int(tick), int(team_id), int(service_number)) in valid_flags: continue
                targets[service].append({
                    "ip": f"10.60.{team_id}.1",
                    "extra": json.dumps(flagId),
                })

    # if get_cur_tick() % CLEAR_RATE == 0: clear_valid_flags()

    return dict(targets)


def parse_submission(sub: FlagSubmission) -> FlagStatus:
    status = sub.status
    msg = sub.msg.lower()

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

    data = requests.put(CC_SUBMIT_ENDPOINT, headers={
        'X-Team-Token': CC_TEAM_TOKEN
    }, json=_flags).json()

    result = [FlagStatus.ERROR]*len(_flags)
    for flag_response in data:
        submission = FlagSubmission(
            msg=flag_response.get("msg", ""),
            flag=flag_response.get("flag", ""),
            status=flag_response.get("status", "")
        )
        flag = submission.flag
        status = parse_submission(submission)
        result[flags[flag]] = status
        if status == FlagStatus.OK:
            valid_flags.add(parse_flag(flag))
    return result
