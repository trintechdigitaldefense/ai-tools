---
name: aleph-dev
description: Build on Aleph Cloud — messages API, persistent storage, serverless programs, VM instances, and indexing.
---

# Aleph Cloud Development

Everything on Aleph is a signed message: POST (data), AGGREGATE (key-value), STORE (files), PROGRAM (serverless), INSTANCE (VMs).

- **API**: `https://api2.aleph.im`
- **Docs**: https://docs.aleph.im

## Workflow 1: Query Messages

```
web_fetch: url=https://api2.aleph.im/api/v0/messages.json?msgType=POST&channels=my-app&page=1&pagination=20
```

Filter by sender:
```
web_fetch: url=https://api2.aleph.im/api/v0/messages.json?addresses=0xYOUR_ADDR&msgType=AGGREGATE
```

Filters: `msgType`, `channels`, `addresses`, `tags`, `hashes`, `refs`, `contentTypes`, `startDate`, `endDate`, `page`, `pagination`.

## Workflow 2: POST Messages (App Data)

```
bash: python3 -c "
import json, hashlib, time
from eth_account import Account
from eth_account.messages import encode_defunct

KEY = 'YOUR_PRIVATE_KEY'
acct = Account.from_key(KEY)

content = {'type':'my-data','body':{'title':'Hello'},'address':acct.address,'time':time.time()}
item_content = json.dumps(content, separators=(',',':'))
item_hash = hashlib.sha256(item_content.encode()).hexdigest()

msg = {'chain':'ETH','sender':acct.address,'type':'POST','channel':'my-app',
       'item_type':'inline','item_content':item_content,'item_hash':item_hash,'time':time.time()}

sig = acct.sign_message(encode_defunct(text=json.dumps(msg, separators=(',',':'))))
msg['signature'] = sig.signature.hex()

with open('/tmp/aleph_msg.json','w') as f: json.dump(msg, f)
print('Ready:', item_hash[:16])
"
```

```
bash: curl -X POST https://api2.aleph.im/api/v0/messages -H 'Content-Type: application/json' -d @/tmp/aleph_msg.json
```

## Workflow 3: AGGREGATE (Key-Value Store)

Read aggregates (mutable per-address key-value):
```
web_fetch: url=https://api2.aleph.im/api/v0/aggregates/{ADDR}.json?keys=profile,settings
```

Update by posting an AGGREGATE message with same key — latest value wins.

## Workflow 4: STORE (Persistent Files → IPFS)

Upload:
```
bash: curl -X POST https://api2.aleph.im/api/v0/storage/add_file -F "file=@/tmp/myfile.json" -F "channel=my-app"
```

Retrieve:
```
web_fetch: url=https://api2.aleph.im/api/v0/storage/raw/{ITEM_HASH}
```

JSON shorthand:
```
bash: curl -X POST https://api2.aleph.im/api/v0/storage/add_json -H 'Content-Type: application/json' -d '{"channel":"my-app","content":{"data":"value"}}'
```

## Workflow 5: PROGRAM (Serverless Functions)

Create function:
```
write_file: path=/tmp/aleph_fn/main.py
```

```python
from aiohttp import web

async def handler(request):
    data = await request.json() if request.content_type == 'application/json' else {}
    return web.json_response({'status':'ok','received':data})

app = web.Application()
app.router.add_route('*', '/{path:.*}', handler)
```

Deploy:
```
bash: pip install aleph-client && aleph program upload /tmp/aleph_fn main:app --channel my-app
```

Access at: `https://api2.aleph.im/vm/{ITEM_HASH}`

## Workflow 6: INSTANCE (Persistent VMs)

```
bash: aleph instance create --channel my-app --memory 2048 --vcpus 2 --rootfs-size 20000 --image debian-12 --ssh-key ~/.ssh/id_rsa.pub
```

Manage:
```
bash: aleph instance list --address 0xYOUR_ADDR
bash: aleph instance stop {HASH}
bash: aleph instance delete {HASH}
```

## Workflow 7: Indexing & Querying

Time-range queries:
```
web_fetch: url=https://api2.aleph.im/api/v0/messages.json?startDate=1700000000&endDate=1710000000&channels=my-app
```

Build local index:
```
bash: python3 -c "
import json, urllib.request
data = json.loads(urllib.request.urlopen('https://api2.aleph.im/api/v0/messages.json?channels=my-app&pagination=200').read())
by_type = {}
for m in data.get('messages', []):
    t = m.get('content', {}).get('type', 'unknown')
    by_type.setdefault(t, []).append(m)
for t, msgs in by_type.items(): print(f'{t}: {len(msgs)}')
"
```

## Authentication

All writes require signed messages. Install: `pip install eth-account web3 aleph-client`

Sign with any EVM private key — the address is your identity, no registration needed.

## Quick Reference

| Op | Endpoint | Method |
|----|----------|--------|
| Read messages | `/api/v0/messages.json` | GET |
| Post message | `/api/v0/messages` | POST |
| Read aggregate | `/api/v0/aggregates/{addr}.json` | GET |
| Upload file | `/api/v0/storage/add_file` | POST |
| Read file | `/api/v0/storage/raw/{hash}` | GET |
| Program | `/vm/{hash}` | * |
