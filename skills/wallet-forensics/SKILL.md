---
name: wallet-forensics
description: Address investigation — profiling, fund tracing, whale tracking, multi-chain correlation, and risk scoring.
---

# Wallet Forensics

Investigate any EVM address. Profile activity, trace funds, detect patterns, score risk.

## Explorers (Same API format, 1 req/5s without key)

- Ethereum: `https://api.etherscan.io/api`
- Polygon: `https://api.polygonscan.com/api`
- Arbitrum: `https://api.arbiscan.io/api`
- Base: `https://api.basescan.org/api`

## Workflow 1: Address Profiling

```
web_fetch: url=https://api.etherscan.io/api?module=account&action=balance&address={ADDR}&tag=latest
```

First transaction (wallet age):
```
web_fetch: url=https://api.etherscan.io/api?module=account&action=txlist&address={ADDR}&startblock=0&endblock=99999999&page=1&offset=1&sort=asc
```

Recent activity + token holdings + NFTs:
```
web_fetch: url=https://api.etherscan.io/api?module=account&action=txlist&address={ADDR}&page=1&offset=20&sort=desc
web_fetch: url=https://api.etherscan.io/api?module=account&action=tokentx&address={ADDR}&page=1&offset=50&sort=desc
web_fetch: url=https://api.etherscan.io/api?module=account&action=tokennfttx&address={ADDR}&page=1&offset=20&sort=desc
```

## Workflow 2: Transaction Flow Analysis

```
bash: python3 -c "
from collections import Counter
txs = []  # parsed tx list
ADDR = '{ADDR}'.lower()
inflows = [(t['from'], float(t['value'])/1e18) for t in txs if t['to'].lower() == ADDR]
outflows = [(t['to'], float(t['value'])/1e18) for t in txs if t['from'].lower() == ADDR]
for label, flows in [('INFLOWS', inflows), ('OUTFLOWS', outflows)]:
    print(f'=== TOP {label} ===')
    counts = Counter(a for a, _ in flows)
    for addr, count in counts.most_common(5):
        total = sum(v for a, v in flows if a == addr)
        print(f'  {addr[:10]}... | {count} txs | {total:.4f} ETH')
"
```

**Pattern detection**: DCA = regular small buys at intervals. Dump = large single sell after accumulation. Wash = circular flows between 2-3 addresses.

## Workflow 3: Label Identification

```
web_search: query="0x{ADDR}" ethereum label exchange
```

Check if it's a contract:
```
web_fetch: url=https://api.etherscan.io/api?module=contract&action=getsourcecode&address={ADDR}
```

Non-empty `ContractName` = contract. Name reveals purpose (Uniswap, Aave, etc.).

## Workflow 4: Whale Tracking

```
web_fetch: url=https://api.etherscan.io/api?module=token&action=tokenholderlist&contractaddress={TOKEN}&page=1&offset=10
```

Per whale, check recent moves:
```
web_fetch: url=https://api.etherscan.io/api?module=account&action=tokentx&address={WHALE}&contractaddress={TOKEN}&page=1&offset=10&sort=desc
```

Flag: whale moved >1% circulating in 7 days.

## Workflow 5: Multi-Chain Scan

```
bash: python3 -c "
chains = {'ethereum':'https://api.etherscan.io/api','polygon':'https://api.polygonscan.com/api',
          'arbitrum':'https://api.arbiscan.io/api','base':'https://api.basescan.org/api'}
ADDR = '{ADDR}'
for chain, base in chains.items():
    print(f'{chain}: {base}?module=account&action=balance&address={ADDR}&tag=latest')
"
```

Run each URL via `web_fetch`. Non-zero = active. Also:
```
web_search: query="0x{ADDR}" bridge transfer polygon arbitrum base
```

## Workflow 6: Risk Scoring

```
bash: python3 -c "
factors = {
    'Funds from known mixer (Tornado Cash)': 25,
    'Interacted with sanctioned address': 25,
    'Wallet age <30d with large balance': 10,
    'Rapid token cycling (buy-sell <hours)': 10,
    'Only no-KYC exchange sources': 10,
    'Multi-chain dust pattern': 5,
    'Unverified contract interactions': 10,
    'High freq trading (>50 tx/day)': 5,
}
triggered = {}  # fill True/False
score = sum(v for k, v in factors.items() if triggered.get(k, False))
print(f'Risk: {score}/100 — {\"HIGH\" if score>=50 else \"MEDIUM\" if score>=25 else \"LOW\"}')
"
```

## Output Report

```
write_file: path=/tmp/report_{ADDR[:8]}.md
```

```
# Wallet Investigation: {ADDR}
## Summary
- Chains: Ethereum, ...  |  Age: X days  |  Balance: X ETH
- Tx Count: X  |  Risk: X/100 (LOW/MED/HIGH)
## Top Fund Sources
| Source | Txs | ETH | Label |
## Top Destinations
| Dest | Txs | ETH | Label |
## Token Holdings
| Token | Balance | USD |
## Patterns: DCA / Dumps / Wash / Mixer / Bridge
## Multi-Chain: Chain | Balance | Last Active
## Risk Flags: 🚩/✅ per factor
```
