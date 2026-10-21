"""Minutes after each day's release at which the team solved every route (read-only).

Run on the Homebase (it lists through the proxy): python3 -I solvetimes.py [first_day]
(default: the last six days; each day's list takes ~2-4 s). The last flag of a day is when
the whole team was done; the slowest lane is the one to automate next. Releases are 09:00
New York. Lists by day, since the lane filter misses Binary (`lane=binary` lists nothing).
"""

from __future__ import annotations

from datetime import datetime, timedelta
import json
import os
import sys
from urllib.request import urlopen
from zoneinfo import ZoneInfo

PROXY = os.environ.get("HUNTRESS_GM_URL", "http://10.0.0.219/huntress-ctf-proxy")
MODES = {"single_solve": "S", "time_trial": "T", "mastery": "M"}
NEW_YORK = ZoneInfo("America/New_York")


def records(day: int) -> list[dict]:
    with urlopen(f"{PROXY}?op=list&day={day}&all=1", timeout=120) as response:
        data = json.load(response)
    return [record for record in data.get("challenges", []) if isinstance(record, dict)]


def main() -> None:
    today = datetime.now(NEW_YORK).day
    first = int(sys.argv[1]) if len(sys.argv) > 1 else max(1, today - 5)
    table: dict[int, dict[str, float]] = {}
    who: dict[str, dict[str, int]] = {}
    for number in range(first, today + 1):
        for record in records(number):
            at, day, lane = (record.get("solved_by") or {}).get("at"), record.get("day"), str(record.get("lane"))
            if not at or not isinstance(day, int) or day != number:
                continue
            release = datetime(2026, 10, day, 9, 0, tzinfo=NEW_YORK)
            solved = datetime.fromisoformat(at.replace("Z", "+00:00"))
            key = f"{lane.split('-')[0][:8]}.{MODES.get(record.get('mode'), '?')}"
            table.setdefault(day, {})[key] = (solved - release) / timedelta(minutes=1)
            name = (record.get("solved_by") or {}).get("name") or "?"
            who.setdefault(lane, {})[name] = who.get(lane, {}).get(name, 0) + 1
    columns = sorted({key for row in table.values() for key in row})
    print("day " + " ".join(f"{column:>11}" for column in columns) + "   last flag")
    for day in sorted(table):
        row = table[day]
        cells = " ".join(f"{row[c]:11.1f}" if c in row else f"{'-':>11}" for c in columns)
        slowest = max(row, key=row.get)
        print(f"{day:3} {cells}   {row[slowest]:.1f} ({slowest})")
    print("solved by:", json.dumps(who, ensure_ascii=True))


if __name__ == "__main__":
    main()
