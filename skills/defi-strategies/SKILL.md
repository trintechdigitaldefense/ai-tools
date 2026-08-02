---
name: defi-strategies
description: Actionable DeFi analysis — yield comparison, impermanent loss calculation, protocol risk, and portfolio optimization.
---

# DeFi Strategies

Find yield, quantify risk, calculate IL, build defensible positions.

## APIs

- DeFiLlama Yields: `https://yields.llama.fi/pools`
- DeFiLlama TVL: `https://api.llama.fi/protocol/{slug}`
- CoinGecko: `https://api.coingecko.com/api/v3`

## Workflow 1: Yield Discovery

```
bash: curl -s https://yields.llama.fi/pools > /tmp/pools.json
```

```
bash: python3 -c "
import json
pools = json.load(open('/tmp/pools.json'))['data']
filtered = [p for p in pools if p.get('stablecoin') and p.get('tvlUsd',0) > 1e6
            and p.get('chain') in ('Ethereum','Arbitrum','Base','Polygon')]
filtered.sort(key=lambda x: x.get('apy',0), reverse=True)
print(f'{\"Pool\":<35} {\"Chain\":<10} {\"APY\":>7} {\"TVL\":>13}')
for p in filtered[:20]:
    print(f'{p[\"symbol\"]:<35} {p[\"chain\"]:<10} {p[\"apy\"]:>6.2f}% {p[\"tvlUsd\"]:>12,.0f}')
"
```

**APY vs APR**: APY includes compounding. Convert: `APY = (1 + APR/n)^n - 1`.

## Workflow 2: Impermanent Loss Calculator

```
bash: python3 -c "
import math
def il(r): return 2*math.sqrt(r)/(1+r) - 1
print(f'{\"Ratio\":<10} {\"IL%\":>8} {\"Loss/10k\":>10}')
for r in [0.5, 0.75, 1.0, 1.25, 1.5, 2.0, 3.0, 5.0]:
    loss = il(r)
    print(f'{r:<10.2f} {loss*100:>7.2f}% {loss*10000:>9,.0f}')
"
```

**When IL kills you**: >5x divergence → >25% IL. Mitigation: stable pairs (USDC/USDT ≈ 0 IL), same-peg (stETH/ETH), or tight Uni V3 ranges with active management.

## Workflow 3: LP Position P&L

```
bash: python3 -c "
entry, current, fees, rewards, gas, days = 10000, 9500, 800, 200, 50, 90
net = current + fees + rewards - entry - gas
roi = net / entry * 100
print(f'Entry: \${entry:,} | Current: \${current:,} | Fees: \${fees:,} | Rewards: \${rewards:,}')
print(f'Gas: \${gas} | Net P&L: \${net:,} | ROI: {roi:.1f}% | Ann: {roi*365/days:.1f}%')
"
```

## Workflow 4: Protocol Risk Assessment

```
web_fetch: url=https://api.llama.fi/protocol/{slug}
```

```
web_search: query="{protocol} smart contract audit report"
```

Scorecard:
```
bash: python3 -c "
checks = {
    'Smart Contract': ['Audited by top firm', 'Bug bounty active', 'Not upgradeable', '>6mo production'],
    'Oracle': ['Chainlink or equiv', 'No custom oracle', 'Multi-oracle fallback'],
    'Governance': ['Timelock on admin', 'Multisig required', 'No single admin key'],
    'Liquidity': ['TVL stable/growing', 'Reward inflation <50%', 'No mandatory lockup'],
}
for cat, items in checks.items():
    print(f'\\n=== {cat} ===')
    for item in items:
        print(f'  [ ] {item}')
"
```

## Workflow 5: Stablecoin Yield Comparison

```
bash: python3 -c "
import json
pools = json.load(open('/tmp/pools.json'))['data']
stables = ['USDC','USDT','DAI']
lending = [p for p in pools if any(s in p.get('symbol','') for s in stables)
           and p.get('tvlUsd',0)>5e6
           and p.get('project') in ('aave-v3','compound-v3','morpho','spark')]
lending.sort(key=lambda x: x.get('apy',0), reverse=True)
print(f'{\"Protocol\":<15} {\"Asset\":<10} {\"Chain\":<10} {\"APY\":>7} {\"TVL\":>12}')
for p in lending[:15]:
    print(f'{p[\"project\"]:<15} {p[\"symbol\"]:<10} {p[\"chain\"]:<10} {p[\"apy\"]:>6.2f}% {p[\"tvlUsd\"]:>11,.0f}')
"
```

## Workflow 6: Gas-Aware Rebalancing

```
bash: python3 -c "
pos, drift, gas, improvement = 10000, 5, 8, 0.5  # USD, %, USD, % APR
annual_gain = pos * improvement / 100
breakeven = gas / (annual_gain / 365)
print(f'Drift: {drift}% | Gas: \${gas} | Breakeven: {breakeven:.0f}d')
print('Rebalance' if breakeven < 30 else 'Skip — gas exceeds benefit')
"
```

## Risk Checklist (Every Position)

| Risk | Check | How |
|------|-------|-----|
| Smart contract | Audit exists, >6mo old | `web_search` |
| Oracle | Chainlink or equivalent | Protocol docs |
| Governance | Multisig + timelock | Etherscan |
| Liquidity | TVL stable/growing | DeFiLlama |
| IL | Price correlation >0.9 | CoinGecko history |
| Regulatory | Not securities-like | `web_search` |
| Gas | Entry+exit < 7d yield | Gas estimator |
