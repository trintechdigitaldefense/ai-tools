---
name: poly-sport
description: "Analyze Polymarket sports markets with bookmaker cross-checks, probability thresholds, market verification, and strict trading guardrails. Use for sports betting, Polymarket positions, redeem checks, market scanning, and bet review."
---
# Polymarket Sports Betting

Analyze sports markets on Polymarket with strict guardrails.

## Hard Rules

- **Sports only.** Do not use this skill for politics, crypto, geopolitics, or celebrity markets.
- **Favorites only.** Prefer outcomes with strong bookmaker support. Default floor: **65% implied probability** from reputable books.
- **No blind execution.** Never place a trade until the exact market, outcome, and token mapping have been verified.
- **No fake precision.** If prices, kickoff times, or market mappings cannot be confirmed live, say so.
- **No guarantee language.** Present bets as probabilities and expected value, never as certainties.

## Default Workflow

### 1. Scan the market
Use web sources or scripts to gather:
- event name
- sport / league
- kickoff or resolution time
- bookmaker odds from multiple reputable books
- current Polymarket market and displayed price

### 2. Convert odds to implied probability
For decimal odds:

```text
implied_probability = 1 / decimal_odds
```

When multiple bookmaker prices are available:
- compute the implied probability for each book
- use an average or a conservative consensus
- prefer broad market agreement over one outlier book

### 3. Filter aggressively
Keep only picks that satisfy all of the following:
- bookmaker consensus supports the outcome
- implied probability is at least **65%**
- the event has **not** started yet
- the Polymarket market clearly exists
- the chosen outcome is the correct one for that market

If nothing qualifies, say: **no qualifying bets right now**.

### 4. Verify the market before any trade
Before recommending or executing anything, verify all of these:
- market title matches the intended event
- outcome label matches the intended side
- event date matches the intended fixture
- token / asset ID belongs to that exact market outcome
- current displayed price is still within acceptable range

If any one of these checks fails, **stop**.

### 5. Present picks clearly
Use a compact format like:

```text
Game: Cavaliers vs 76ers
Pick: Cavaliers
Bookmaker probability: 85.1%
Polymarket price: 0.84
Edge: +1.1%
Kickoff: 2026-03-09 19:00 ET
Status: qualifies
```

Always include caveats when relevant:
- football three-way markets are harder to compare to yes/no or side markets
- low liquidity can distort price
- stale odds weaken confidence

### 6. Require explicit approval before execution
If the user wants execution, restate the trade in plain English first:
- event
- side
- price
- size
- reason it qualifies

Then execute only after approval.

## Position and Redeem Checks

When checking an existing Polymarket wallet:
- list each open position
- show stake / average price / current value if available
- mark positions as **open**, **redeemable**, or **resolved-losing**
- separate wallet cash from position value

When redeemable positions exist:
- say exactly which positions are redeemable
- do not say a position is redeemable unless a live check confirms it

## Recommended Output Style

Use short, decision-ready summaries:

```text
Wallet cash: $2.94
Open positions value: $21.45
Redeemable now: Cavaliers ($5.90)
```

Then provide the detailed breakdown underneath.

## Red Flags

Stop and warn the user if:
- the market mapping looks wrong
- the same token appears to resolve to a different event than expected
- the event already started
- only one weak source supports the odds
- the edge exists only because the data is stale
- the market is outside sports

## Good Operating Habits

- Prefer fewer, higher-conviction bets over many marginal bets.
- Re-check price and market mapping immediately before execution.
- After any execution mistake, stop and diagnose before placing another order.
- For wallet questions, favor live position data over memory.
- Keep explanations concise unless the user asks for the math.
