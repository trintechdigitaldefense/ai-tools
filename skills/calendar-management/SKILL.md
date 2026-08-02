---
name: calendar-management
description: "View, create, update, and delete calendar events via CalDAV. Supports Google Calendar, Outlook, iCloud, and any CalDAV provider."
---
# Calendar Management

View, create, update, and delete calendar events via CalDAV protocol. Works with Google Calendar, Outlook, iCloud, and any CalDAV-compatible provider.

## Setup

### Install CalDAV library
On first use, install the `caldav` Python package using the agent venv:
```
bash: /opt/baal-agent/bin/pip install caldav 2>/dev/null || pip3 install caldav
```

### Credentials

Calendar credentials are stored in `workspace/config/calendar.json`. On first use, ask the user for their CalDAV provider, URL, username, and password, then save:
```
bash: mkdir -p workspace/config && cat > workspace/config/calendar.json << 'EOF'
{
  "caldav_url": "https://caldav.icloud.com",
  "caldav_user": "user@icloud.com",
  "caldav_password": "xxxx-xxxx-xxxx-xxxx"
}
EOF
```

All Python snippets below load credentials from this file:
```python
import json
with open('workspace/config/calendar.json') as f:
    cfg = json.load(f)
CALDAV_URL = cfg['caldav_url']
CALDAV_USER = cfg['caldav_user']
CALDAV_PASSWORD = cfg['caldav_password']
```

### Provider Quick Reference

| Provider | CalDAV URL | Notes |
|---|---|---|
| **Google Calendar** | `https://www.googleapis.com/caldav/v2/calendarserver/webdav/` | Use App Password with 2FA |
| **iCloud** | `https://caldav.icloud.com` | Requires App-Specific Password |
| **Outlook/Office 365** | Not natively CalDAV — see workaround below | Use GRAPH API approach |
| **Nextcloud** | `https://your-server.com/remote.php/dav` | Standard CalDAV |
| **Fastmail** | `https://caldav.fastmail.com/dav/calendars/user/EMAIL/` | Standard CalDAV |
| **Radicale** | `http://localhost:5232` | Self-hosted CalDAV |

### Check Configuration
```
bash: python3 -c "import json, os; cfg=json.load(open('workspace/config/calendar.json')) if os.path.exists('workspace/config/calendar.json') else {}; print('Calendar configured' if cfg.get('caldav_url') else 'NOT CONFIGURED: Ask the user for CalDAV credentials')"
```

## Viewing Events

### List upcoming events (next 7 days)
```
bash: python3 << 'PYEOF'
import caldav
from datetime import datetime, timedelta

import json
with open('workspace/config/calendar.json') as f:
    cfg = json.load(f)
client = caldav.DAVClient(
    url=cfg['caldav_url'],
    username=cfg['caldav_user'],
    password=cfg['caldav_password']
)
principal = client.principal()
calendars = principal.calendars()

now = datetime.now()
end = now + timedelta(days=7)

for cal in calendars:
    print(f"\n📅 Calendar: {cal.name}")
    events = cal.search(start=now, end=end, event=True, expand=True)
    if not events:
        print("  No upcoming events")
        continue
    for event in sorted(events, key=lambda e: str(e.vobject_instance.vevent.dtstart.value)):
        ev = event.vobject_instance.vevent
        summary = str(ev.summary.value) if hasattr(ev, 'summary') else '(no title)'
        dtstart = ev.dtstart.value
        dtend = ev.dtend.value if hasattr(ev, 'dtend') else ''
        location = str(ev.location.value) if hasattr(ev, 'location') else ''
        loc_str = f" @ {location}" if location else ""
        print(f"  {dtstart} - {dtend}{loc_str} | {summary}")
PYEOF
```

### List events for a specific date range
```
bash: python3 << 'PYEOF'
import caldav
from datetime import datetime

import json
with open('workspace/config/calendar.json') as f:
    cfg = json.load(f)
client = caldav.DAVClient(
    url=cfg['caldav_url'],
    username=cfg['caldav_user'],
    password=cfg['caldav_password']
)
principal = client.principal()
calendars = principal.calendars()

start = datetime(2025, 3, 1)  # CHANGE ME
end = datetime(2025, 3, 31)    # CHANGE ME

for cal in calendars:
    events = cal.search(start=start, end=end, event=True, expand=True)
    for event in events:
        ev = event.vobject_instance.vevent
        summary = str(ev.summary.value) if hasattr(ev, 'summary') else '(no title)'
        print(f"{ev.dtstart.value} | {cal.name} | {summary}")
PYEOF
```

### List all calendars
```
bash: python3 -c "
import caldav
import json
with open('workspace/config/calendar.json') as f:
    cfg = json.load(f)
client = caldav.DAVClient(url=cfg['caldav_url'], username=cfg['caldav_user'], password=cfg['caldav_password'])
for cal in client.principal().calendars():
    print(f'{cal.name} ({cal.id})')
"
```

## Creating Events

### Create a simple event
```
bash: python3 << 'PYEOF'
import caldav
from datetime import datetime

import json
with open('workspace/config/calendar.json') as f:
    cfg = json.load(f)
client = caldav.DAVClient(
    url=cfg['caldav_url'],
    username=cfg['caldav_user'],
    password=cfg['caldav_password']
)
calendar = client.principal().calendars()[0]  # first calendar

ical = """BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//LiberClaw//Agent//EN
BEGIN:VEVENT
SUMMARY:EVENT_TITLE_HERE
DTSTART:20250325T140000
DTEND:20250325T150000
LOCATION:LOCATION_HERE
DESCRIPTION:DESCRIPTION_HERE
END:VEVENT
END:VCALENDAR"""

calendar.save_event(ical)
print("Event created successfully")
PYEOF
```

Date format: `YYYYMMDDTHHMMSS` (local time) or `YYYYMMDDTHHMMSSZ` (UTC).

### Create an all-day event
```
bash: python3 << 'PYEOF'
import caldav

import json
with open('workspace/config/calendar.json') as f:
    cfg = json.load(f)
client = caldav.DAVClient(
    url=cfg['caldav_url'],
    username=cfg['caldav_user'],
    password=cfg['caldav_password']
)
calendar = client.principal().calendars()[0]

ical = """BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//LiberClaw//Agent//EN
BEGIN:VEVENT
SUMMARY:EVENT_TITLE_HERE
DTSTART;VALUE=DATE:20250325
DTEND;VALUE=DATE:20250326
DESCRIPTION:DESCRIPTION_HERE
END:VEVENT
END:VCALENDAR"""

calendar.save_event(ical)
print("All-day event created")
PYEOF
```

### Create a recurring event
```
bash: python3 << 'PYEOF'
import caldav

import json
with open('workspace/config/calendar.json') as f:
    cfg = json.load(f)
client = caldav.DAVClient(
    url=cfg['caldav_url'],
    username=cfg['caldav_user'],
    password=cfg['caldav_password']
)
calendar = client.principal().calendars()[0]

# RRULE examples:
# FREQ=DAILY;COUNT=10          — daily for 10 days
# FREQ=WEEKLY;BYDAY=MO,WE,FR  — every Mon/Wed/Fri
# FREQ=MONTHLY;BYMONTHDAY=15  — 15th of every month
# FREQ=YEARLY                  — every year

ical = """BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//LiberClaw//Agent//EN
BEGIN:VEVENT
SUMMARY:Weekly Team Standup
DTSTART:20250325T090000
DTEND:20250325T093000
RRULE:FREQ=WEEKLY;BYDAY=MO,WE,FR
DESCRIPTION:Daily standup meeting
END:VEVENT
END:VCALENDAR"""

calendar.save_event(ical)
print("Recurring event created")
PYEOF
```

## Updating Events

### Find and update an event
```
bash: python3 << 'PYEOF'
import caldav
from datetime import datetime, timedelta

import json
with open('workspace/config/calendar.json') as f:
    cfg = json.load(f)
client = caldav.DAVClient(
    url=cfg['caldav_url'],
    username=cfg['caldav_user'],
    password=cfg['caldav_password']
)
calendar = client.principal().calendars()[0]

# Search for the event to update
events = calendar.search(start=datetime.now(), end=datetime.now() + timedelta(days=30), event=True)
for event in events:
    ev = event.vobject_instance.vevent
    if 'SEARCH_TERM' in str(ev.summary.value):
        # Modify the event
        ev.summary.value = 'NEW_TITLE_HERE'
        # ev.dtstart.value = datetime(2025, 3, 26, 15, 0)  # reschedule
        # ev.location.value = 'New Location'
        event.save()
        print(f'Updated: {ev.summary.value}')
        break
PYEOF
```

## Deleting Events

### Delete an event by title search
```
bash: python3 << 'PYEOF'
import caldav
from datetime import datetime, timedelta

import json
with open('workspace/config/calendar.json') as f:
    cfg = json.load(f)
client = caldav.DAVClient(
    url=cfg['caldav_url'],
    username=cfg['caldav_user'],
    password=cfg['caldav_password']
)
calendar = client.principal().calendars()[0]

events = calendar.search(start=datetime.now() - timedelta(days=30), end=datetime.now() + timedelta(days=365), event=True)
for event in events:
    ev = event.vobject_instance.vevent
    if 'EVENT_TITLE_TO_DELETE' in str(ev.summary.value):
        print(f'Deleting: {ev.summary.value} on {ev.dtstart.value}')
        event.delete()
        print('Deleted successfully')
        break
PYEOF
```

## Outlook / Microsoft 365 Workaround

Outlook doesn't support CalDAV natively. Use the ICS subscription URL or bash+curl with Microsoft Graph API:

### List events via Graph API (requires OAuth token)
```
bash: curl -s -H "Authorization: Bearer ACCESS_TOKEN_HERE" \
  "https://graph.microsoft.com/v1.0/me/events?\$top=10&\$orderby=start/dateTime&\$select=subject,start,end,location" \
  | python3 -c "import json,sys; data=json.load(sys.stdin); [print(f\"{e['start']['dateTime'][:16]} | {e['subject']} | {e.get('location',{}).get('displayName','')}\") for e in data.get('value',[])]"
```

For Outlook, recommend the user use the web console or connect via a CalDAV bridge like DavMail.

## Safety Rules

- **ALWAYS confirm with the user before creating, updating, or deleting events.**
- Show event details (title, date, time, location) before creating.
- When deleting, confirm the exact event title and date.
- Be careful with recurring events — clarify if the user wants to modify one occurrence or the entire series.
- Save the user's preferred calendar name to memory for future use.

## Tips

- Install `caldav` on first use — it's not pre-installed on the agent VM.
- Google Calendar CalDAV requires an App Password, not the regular Google password.
- Save the user's timezone to `workspace/memory/MEMORY.md` for correct event times.
- When creating events, always confirm the timezone with the user.
- For quick scheduling, suggest the user connect their primary calendar and save CalDAV credentials via chat.
- Use `spawn` to check calendar while doing other tasks in parallel.
