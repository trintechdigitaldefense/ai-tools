---
name: email-management
description: "Read, send, delete, organize emails via IMAP/SMTP. Supports Gmail, Outlook, iCloud, and any IMAP provider."
---
# Email Management

Read, send, delete, and organize emails via IMAP/SMTP. Works with Gmail, Outlook/Hotmail, iCloud, and any standard IMAP/SMTP provider.

## Setup

Email credentials are stored in `workspace/config/email.json`. On first use, ask the user for their email provider and credentials, then save:
```
bash: mkdir -p workspace/config && cat > workspace/config/email.json << 'EOF'
{
  "imap_host": "imap.gmail.com",
  "imap_port": 993,
  "smtp_host": "smtp.gmail.com",
  "smtp_port": 587,
  "user": "user@gmail.com",
  "password": "xxxx xxxx xxxx xxxx"
}
EOF
```

All Python snippets below load credentials from this file:
```python
import json
with open('workspace/config/email.json') as f:
    cfg = json.load(f)
```

### Provider Quick Reference

| Provider | IMAP Host | SMTP Host | Notes |
|---|---|---|---|
| **Gmail** | `imap.gmail.com:993` | `smtp.gmail.com:587` | Requires App Password (2FA must be enabled) |
| **Outlook/Hotmail** | `outlook.office365.com:993` | `smtp.office365.com:587` | Use regular password or App Password |
| **iCloud** | `imap.mail.me.com:993` | `smtp.mail.me.com:587` | Requires App-Specific Password |
| **Yahoo** | `imap.mail.yahoo.com:993` | `smtp.mail.yahoo.com:587` | Requires App Password |
| **Custom IMAP** | Provider-specific | Provider-specific | Check provider docs |

## Checking for Email Configuration

Before any email operation, verify credentials are saved:
```
bash: python3 -c "import json, os; cfg=json.load(open('workspace/config/email.json')) if os.path.exists('workspace/config/email.json') else {}; print('Email configured' if cfg.get('imap_host') else 'NOT CONFIGURED: Ask the user for email credentials')"
```

If not configured, ask the user for their email provider, address, and App Password. Never ask the user to redeploy.

## Reading Emails

### List recent emails from inbox
```
bash: python3 -c "
import imaplib, email
from email.header import decode_header

import json
with open('workspace/config/email.json') as f:
    cfg = json.load(f)
M = imaplib.IMAP4_SSL(cfg['imap_host'], int(cfg.get('imap_port', 993)))
M.login(cfg['user'], cfg['password'])
M.select('INBOX')
_, nums = M.search(None, 'ALL')
ids = nums[0].split()[-20:]  # last 20
for i in reversed(ids):
    _, data = M.fetch(i, '(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])')
    msg = email.message_from_bytes(data[0][1])
    subj = decode_header(msg['Subject'] or '(no subject)')[0]
    subj_str = subj[0].decode(subj[1] or 'utf-8') if isinstance(subj[0], bytes) else str(subj[0])
    frm = msg['From'] or 'unknown'
    date = msg['Date'] or ''
    print(f'ID:{i.decode()} | {date[:22]} | {frm[:40]} | {subj_str[:60]}')
M.logout()
"
```

### Read a specific email by ID
```
bash: python3 -c "
import imaplib, email, sys
from email.header import decode_header

msg_id = 'MSG_ID_HERE'
import json
with open('workspace/config/email.json') as f:
    cfg = json.load(f)
M = imaplib.IMAP4_SSL(cfg['imap_host'], int(cfg.get('imap_port', 993)))
M.login(cfg['user'], cfg['password'])
M.select('INBOX')
_, data = M.fetch(msg_id.encode(), '(RFC822)')
msg = email.message_from_bytes(data[0][1])

subj = decode_header(msg['Subject'] or '')[0]
subj_str = subj[0].decode(subj[1] or 'utf-8') if isinstance(subj[0], bytes) else str(subj[0])
print(f'From: {msg[\"From\"]}')
print(f'To: {msg[\"To\"]}')
print(f'Date: {msg[\"Date\"]}')
print(f'Subject: {subj_str}')
print('---')
if msg.is_multipart():
    for part in msg.walk():
        if part.get_content_type() == 'text/plain':
            charset = part.get_content_charset() or 'utf-8'
            print(part.get_payload(decode=True).decode(charset, errors='replace'))
            break
else:
    charset = msg.get_content_charset() or 'utf-8'
    print(msg.get_payload(decode=True).decode(charset, errors='replace'))
M.logout()
"
```

Replace `MSG_ID_HERE` with the actual message ID from the listing.

### Search emails
```
bash: python3 -c "
import imaplib, email
from email.header import decode_header

import json
with open('workspace/config/email.json') as f:
    cfg = json.load(f)
M = imaplib.IMAP4_SSL(cfg['imap_host'], int(cfg.get('imap_port', 993)))
M.login(cfg['user'], cfg['password'])
M.select('INBOX')
# IMAP search criteria: FROM, TO, SUBJECT, BODY, SINCE, BEFORE, UNSEEN, FLAGGED
_, nums = M.search(None, 'SUBJECT', '\"SEARCH_TERM_HERE\"')
ids = nums[0].split()[-20:]
for i in reversed(ids):
    _, data = M.fetch(i, '(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])')
    msg = email.message_from_bytes(data[0][1])
    subj = decode_header(msg['Subject'] or '')[0]
    subj_str = subj[0].decode(subj[1] or 'utf-8') if isinstance(subj[0], bytes) else str(subj[0])
    print(f'ID:{i.decode()} | {msg[\"From\"][:40]} | {subj_str[:60]}')
M.logout()
"
```

### Common IMAP search filters
- `UNSEEN` — unread emails
- `FLAGGED` — starred/flagged emails
- `FROM "sender@example.com"` — from specific sender
- `SUBJECT "keyword"` — subject contains keyword
- `SINCE "01-Jan-2025"` — emails after date
- `BEFORE "01-Mar-2025"` — emails before date
- `BODY "keyword"` — body contains keyword
- Combine: `(UNSEEN FROM "boss@company.com")`

## Sending Emails

### Send a new email
```
bash: python3 -c "
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

msg = MIMEMultipart()
msg['From'] = cfg['user']
msg['To'] = 'RECIPIENT_HERE'
msg['Subject'] = 'SUBJECT_HERE'
msg.attach(MIMEText('BODY_TEXT_HERE', 'plain'))

with smtplib.SMTP(cfg['smtp_host'], int(cfg.get('smtp_port', 587))) as s:
    s.starttls()
    s.login(cfg['user'], cfg['password'])
    s.send_message(msg)
print('Email sent successfully')
"
```

### Reply to an email
When replying, include `In-Reply-To` and `References` headers, and prefix subject with `Re:`:
```
bash: python3 -c "
import smtplib, imaplib, email
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Fetch original for headers
import json
with open('workspace/config/email.json') as f:
    cfg = json.load(f)
M = imaplib.IMAP4_SSL(cfg['imap_host'], int(cfg.get('imap_port', 993)))
M.login(cfg['user'], cfg['password'])
M.select('INBOX')
_, data = M.fetch(b'MSG_ID_HERE', '(RFC822)')
orig = email.message_from_bytes(data[0][1])
M.logout()

reply = MIMEMultipart()
reply['From'] = cfg['user']
reply['To'] = orig['Reply-To'] or orig['From']
reply['Subject'] = 'Re: ' + (orig['Subject'] or '')
reply['In-Reply-To'] = orig['Message-ID']
reply['References'] = (orig.get('References', '') + ' ' + orig['Message-ID']).strip()
reply.attach(MIMEText('REPLY_BODY_HERE', 'plain'))

with smtplib.SMTP(cfg['smtp_host'], int(cfg.get('smtp_port', 587))) as s:
    s.starttls()
    s.login(cfg['user'], cfg['password'])
    s.send_message(reply)
print('Reply sent successfully')
"
```

## Managing Emails

### Delete an email
```
bash: python3 -c "
import imaplib
import json
with open('workspace/config/email.json') as f:
    cfg = json.load(f)
M = imaplib.IMAP4_SSL(cfg['imap_host'], int(cfg.get('imap_port', 993)))
M.login(cfg['user'], cfg['password'])
M.select('INBOX')
M.store(b'MSG_ID_HERE', '+FLAGS', '\\\\Deleted')
M.expunge()
print('Email deleted')
M.logout()
"
```

### Move email to a folder
```
bash: python3 -c "
import imaplib
import json
with open('workspace/config/email.json') as f:
    cfg = json.load(f)
M = imaplib.IMAP4_SSL(cfg['imap_host'], int(cfg.get('imap_port', 993)))
M.login(cfg['user'], cfg['password'])
M.select('INBOX')
M.copy(b'MSG_ID_HERE', 'FOLDER_NAME_HERE')
M.store(b'MSG_ID_HERE', '+FLAGS', '\\\\Deleted')
M.expunge()
print('Email moved to FOLDER_NAME_HERE')
M.logout()
"
```

### Mark as read / unread
```
bash: python3 -c "
import imaplib
import json
with open('workspace/config/email.json') as f:
    cfg = json.load(f)
M = imaplib.IMAP4_SSL(cfg['imap_host'], int(cfg.get('imap_port', 993)))
M.login(cfg['user'], cfg['password'])
M.select('INBOX')
# Mark as read:
M.store(b'MSG_ID_HERE', '+FLAGS', '\\\\Seen')
# Mark as unread: M.store(b'MSG_ID_HERE', '-FLAGS', '\\\\Seen')
print('Done')
M.logout()
"
```

### List folders
```
bash: python3 -c "
import imaplib
import json
with open('workspace/config/email.json') as f:
    cfg = json.load(f)
M = imaplib.IMAP4_SSL(cfg['imap_host'], int(cfg.get('imap_port', 993)))
M.login(cfg['user'], cfg['password'])
for folder in M.list()[1]:
    print(folder.decode())
M.logout()
"
```

### Flag / star an email
```
bash: python3 -c "
import imaplib
import json
with open('workspace/config/email.json') as f:
    cfg = json.load(f)
M = imaplib.IMAP4_SSL(cfg['imap_host'], int(cfg.get('imap_port', 993)))
M.login(cfg['user'], cfg['password'])
M.select('INBOX')
M.store(b'MSG_ID_HERE', '+FLAGS', '\\\\Flagged')
print('Email flagged')
M.logout()
"
```

## Safety Rules

- **ALWAYS confirm with the user before sending, deleting, or moving emails.**
- Show a preview of the email (recipient, subject, body) before sending.
- When deleting, confirm the email subject/sender first.
- Never expose the email password in output — it's in the config file only.
- When listing emails, show a manageable number (20 max) unless asked for more.

## Tips

- Use `BODY.PEEK` (not `BODY`) when fetching to avoid marking emails as read unintentionally.
- For Gmail, the user needs to create an App Password at https://myaccount.google.com/apppasswords
- For iCloud, App-Specific Passwords at https://appleid.apple.com/account/manage
- Save commonly used email contacts to `workspace/memory/MEMORY.md` for quick reference.
- If the IMAP connection fails, check that the host/port are correct and the password is an App Password (not regular password) for providers that require it.
