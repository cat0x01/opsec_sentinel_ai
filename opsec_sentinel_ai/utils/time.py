from __future__ import annotations

import datetime
import time
from typing import Dict


def local_time_info() -> Dict[str, str]:
    now = datetime.datetime.now()
    utc_offset = time.strftime("%z")
    tzname = time.tzname[0] if time.tzname else "unknown"
    return {
        "local_time": now.isoformat(),
        "utc_offset": utc_offset,
        "timezone_name": tzname,
    }
