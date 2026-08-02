---
name: token-analysis
description: Deep tokenomics analysis — supply dynamics, holder concentration, liquidity depth, unlock tracking, and red flag detection.
---

# Token Analysis

Analyze tokens beyond price. Supply mechanics, holder distribution, liquidity quality, and risk signals.

## API Endpoints (No Key Required)

- CoinGecko: `https://api.coingecko.com/api/v3`
- DeFiLlama: `https://api.llama.fi` / `https://yields.llama.fi`
- Etherscan: `https://api.etherscan.io/api` (1 req/5s without key)

## Workflow 1: Supply Analysis

```
web_fetch: url=https://api.coingecko.com/api/v3/coins/{id}?localization=false&tickers=false&community_data=false&developer_data=false
```

Extract `market_data.circulating_supply`, `total_supply`, `max_supply`. Inflation = `(total - circulating) / circulating * 100`. Null `max_supply` = uncapped, flag it. Verify on-chain:

```
web_fetch: url=https://api.etherscan.io/api?module=stats&action=tokensupply&contractaddress={ADDRESS}
```

## Workflow 2: Holder Concentration (HHI)

```
web_fetch: url=https://api.etherscan.io/api?module=token&action=tokenholderlist&contractaddress={ADDRESS}&page=1&offset=20
```

```
bash: python3 -c "
holders = [15.2, 8.1, 6.3, 4.0, 3.5, 2.1, 1.8, 1.5, 1.2, 1.0]  # top holder %
hhi = sum(h**2 for h in holders)
print(f'HHI: {hhi:.0f}')
print('Highly concentrated' if hhi > 2500 else 'Moderate' if hhi > 1500 else 'Diversified')
"
```

## Workflow 3: Liquidity Analysis

```
web_fetch: url=https://yields.llama.fi/pools
```

Filter by project/symbol. Key metrics:
- **Volume/MCap**: <0.01 illiquid, 0.01-0.05 thin, >0.1 healthy
- **TVL trend**: declining 30d = capital flight
- **Pool concentration**: single pool >80% = fragile

```
bash: python3 -c "
tvl, trade = 500000, 10000
slippage = (trade / tvl) * 100 * 2
print(f'Slippage for \${trade}: {slippage:.2f}%')
print('DANGER' if slippage > 5 else 'OK' if slippage < 2 else 'Caution')
"
```

## Workflow 4: Token Unlock Tracking

```
web_search: query="{token_name} token unlock schedule vesting 2024 2025"
```

Check vesting contract transfers:
```
web_fetch: url=https://api.etherscan.io/api?module=account&action=tokentx&contractaddress={TOKEN}&address={VESTING_CONTRACT}&sort=desc&page=1&offset=10
```

Flag: upcoming unlocks >2% of circulating = significant sell pressure.

## Workflow 5: Red Flag Checklist

```
bash: python3 -c "
flags = {
    'Top 10 hold >50%': False,
    'No locked liquidity': False,
    'Anonymous team': False,
    'Unlock >5% in 30d': False,
    'Vol/MCap <0.01': False,
    'No audit or >1yr old': False,
    'Uncapped supply, no burn': False,
    'Single pool >90% liq': False,
    'Contract unverified': False,
    'Deployer holds >10%': False,
}
score = sum(flags.values())
print(f'Red flags: {score}/10')
print('HIGH RISK' if score >= 4 else 'MODERATE' if score >= 2 else 'LOW RISK')
for f, v in flags.items():
    print(f'  {\"🚩\" if v else \"✅\"} {f}')
"
```

## Workflow 6: Token Comparison

```
bash: python3 -c "
tokens = {'A': {'mcap':0,'circ%':0,'vol_mcap':0,'hhi':0,'flags':0},
          'B': {'mcap':0,'circ%':0,'vol_mcap':0,'hhi':0,'flags':0}}
print(f'{\"Metric\":<12}', *[f'{t:<12}' for t in tokens])
for m in ['mcap','circ%','vol_mcap','hhi','flags']:
    print(f'{m:<12}', *[f'{tokens[t][m]:<12}' for t in tokens])
"
```

## Output Template

```
## Token: {NAME} ({SYMBOL})
**Contract:** {address} | **Chain:** {chain}

### Supply: Circ X | Total Y | Max Z | Inflation X%
### Holders: Top 10 = X% | HHI = X
### Liquidity: TVL $X | Vol/MCap X | Slippage($10k) X%
### Unlocks: Next DATE — X tokens (X% circ)
### Risk: X/10 flags
```
