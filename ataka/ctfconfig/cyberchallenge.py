import json
from datetime import datetime
from ataka.common.flag_status import FlagStatus
import requests
from collections import defaultdict

### EXPORTED CONFIG

CC_TEAM_ID = "6"

# Ataka Host Domain / IP
ATAKA_HOST = 'ataka.h4xx.eu'
GAME_SERVER_IP = '10.10.0.1'

# Default targets for atk runlocal
RUNLOCAL_TARGETS = ["10.60.0.1"]

# IPs that are always excluded from attacks.
STATIC_EXCLUSIONS = {f'10.60.0.{CC_TEAM_ID}', '10.60.0.1'}

ROUND_TIME = 120

# format: regex, group where group 0 means the whole regex
FLAG_REGEX = r"[A-Z0-9]{31}=", 0

FLAG_BATCHSIZE = 69

FLAG_RATELIMIT = 1  # Wait in seconds between each call of submit_flags()

# When the CTF starts
START_TIME = datetime.fromisoformat("2025-06-17T12:34:56+02:00")


### END EXPORTED CONFIG


valid_flags = set()
submitted_flags = set()
services: list[str] = []

def parse_flag(flag: str) -> tuple[int, int, int]:
    round_number = int(flag[0:2], 36)
    team_number = int(flag[2:4], 36)
    service_number = int(flag[4:6], 36)
    return (round_number, team_number, service_number)


def get_targets():
    global services

    r = requests.get(f"http://{GAME_SERVER_IP}:8081/flagIds", timeout=10)
    data = r.json()
    if not services:
        services = list(data.keys())
        print(f"Services: {services}")

    targets = defaultdict(list)

    for service_number, service in enumerate(services):
        for team_id, info in data[service].items():
            for tick, flagId in info.items():
                if (tick, team_id, service_number) in valid_flags: continue
                targets[service].append({
                    "ip": f"10.60.{team_id}.1",
                    "extra": json.dumps(flagId),
                })

    return dict(targets)


def _randomness():
    import random
    return \
        random.choices([FlagStatus.OK, FlagStatus.INVALID, FlagStatus.INACTIVE, FlagStatus.OWNFLAG, FlagStatus.ERROR],
                       weights=[0.5, 0.2, 0.2, 0.05, 0.1], k=1)[0]


def submit_flags(flags):
    import time
    global submitted_flags
    global valid_flags
    time.sleep(min(len(flags) / 1000, 2))
    result = {flag: FlagStatus.DUPLICATE if flag in submitted_flags else _randomness() for flag in flags}
    submitted_flags.update([flag for flag, status in result.items() if status != FlagStatus.ERROR])
    valid_flags.update(set(map(parse_flag, [flag for flag, status in result.items() if status == FlagStatus.OK])))
    return [result[flag] for flag in flags]
