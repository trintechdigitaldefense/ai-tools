---
name: smart-contract-security
description: Deep smart contract vulnerability analysis, audit methodology, and exploit pattern detection
---

# Smart Contract Security

Systematic vulnerability analysis for Solidity smart contracts. Detection patterns, exploit vectors, and audit methodology using static analysis tools.

## Reentrancy Detection

The classic: external call before state update. Scan for it:
```
bash: grep -n "\.call{value" *.sol | while read line; do file=$(echo "$line" | cut -d: -f1); num=$(echo "$line" | cut -d: -f2); echo "=== $file:$num ==="; sed -n "$((num-5)),$((num+10))p" "$file"; done
```

Pattern to flag — state change AFTER external call:
```solidity
// VULNERABLE
function withdraw() external {
    (bool ok,) = msg.sender.call{value: balances[msg.sender]}("");
    balances[msg.sender] = 0; // too late
}
```

Fix: checks-effects-interactions or ReentrancyGuard:
```
bash: grep -rn "nonReentrant\|ReentrancyGuard" *.sol || echo "WARNING: No reentrancy guards found"
```

## Flash Loan Attack Vectors

Detect price-dependent logic vulnerable to manipulation:
```
bash: grep -n "getReserves\|balanceOf\|totalSupply" *.sol | grep -v "//\|TWAP\|oracle"
```

Red flags: spot price from `getReserves()`, single-block price reads, `balanceOf(address(this))` for pricing. Must use TWAP or Chainlink.

## Access Control Audit

Find unprotected state-changing functions:
```
bash: grep -n "function " *.sol | grep -E "external|public" | grep -v "view\|pure\|onlyOwner\|onlyRole\|require.*msg.sender\|_check"
```

Check for `tx.origin` (phishable):
```
bash: grep -n "tx.origin" *.sol && echo "CRITICAL: tx.origin used — vulnerable to phishing"
```

Verify ownership transfer is two-step:
```
bash: grep -n "transferOwnership\|Ownable2Step" *.sol
```

## Integer Issues

Solidity 0.8+ has automatic overflow checks, but `unchecked` blocks bypass them:
```
bash: grep -n "unchecked" *.sol -A 5
```

Every `unchecked` block needs manual review. Common legitimate use: loop counters. Suspicious: token math, balance calculations.

## Front-Running / MEV

Detect vulnerable patterns — state-dependent transactions without slippage protection:
```
bash: grep -n "amountOutMin\|deadline\|slippage" *.sol || echo "WARNING: No slippage protection found in swap functions"
bash: grep -n "swap\|exchange\|trade" *.sol | grep -v "amountOutMin\|minOut"
```

Mitigation: commit-reveal for auctions/votes, slippage params for swaps, private mempools (Flashbots) for sensitive txs.

## Oracle Manipulation

Check oracle usage patterns:
```
bash: grep -n "latestRoundData\|latestAnswer\|getPrice\|consult" *.sol
bash: grep -n "latestRoundData" *.sol -A 5 | grep -v "updatedAt\|answeredInRound" && echo "WARNING: Missing staleness checks"
```

Chainlink must validate: `answeredInRound >= roundId`, `updatedAt > 0`, `answer > 0`, staleness threshold. Uniswap TWAP over 30min minimum for DeFi.

## Proxy & Upgrade Vulnerabilities

```
bash: grep -rn "delegatecall\|ERC1967\|TransparentProxy\|UUPSUpgradeable\|initializ" *.sol
```

Critical checks:
- `initialize()` has `initializer` modifier and can't be called twice
- No `constructor` in implementation (use `_disableInitializers`)
- Storage layout matches between versions (no slot collisions)
- `selfdestruct` in implementation = kills all proxies

Detect storage collision risk:
```
bash: grep -n "uint256\|address\|mapping\|bool" *.sol | head -30  # Compare variable ordering between V1 and V2
```

## Selfdestruct & Delegatecall Risks

```
bash: grep -n "selfdestruct\|delegatecall" *.sol
```

`selfdestruct` sends ETH bypassing `receive()`/`fallback()` — breaks contracts relying on `address(this).balance`. Deprecated post-Dencun but still dangerous on some chains.

`delegatecall` to untrusted targets = full storage takeover. Only delegatecall to known, immutable addresses.

## Gas vs Security Tradeoffs

Patterns that sacrifice security for gas — flag these:
```
bash: grep -n "unchecked\|assembly\|sstore\|sload\|mstore" *.sol | wc -l
```

Assembly blocks need line-by-line review. Never skip bounds checks in assembly to save gas. Prefer `SafeERC20` over raw `.transfer()`.

## Static Analysis Setup

Install and run Slither:
```
bash: pip install slither-analyzer solc-select
bash: solc-select install 0.8.24 && solc-select use 0.8.24
bash: slither . --print human-summary
bash: slither . --detect reentrancy-eth,reentrancy-no-eth,unprotected-upgrade,arbitrary-send-eth,controlled-delegatecall,suicidal
```

Run Mythril for symbolic execution:
```
bash: pip install mythril
bash: myth analyze contracts/Target.sol --solv 0.8.24 --execution-timeout 300
```

## Full Audit Checklist

1. **Scope**: `bash: find . -name "*.sol" -not -path "*/node_modules/*" | xargs wc -l | sort -n`
2. **Dependencies**: `bash: grep -rn "import" *.sol | grep -v "@openzeppelin" | sort -u` — review non-OZ imports
3. **Access control**: Run unprotected function scan above
4. **Reentrancy**: Run call-before-state-update scan
5. **Oracle usage**: Validate staleness checks, TWAP windows
6. **Unchecked blocks**: Manual review each one
7. **External calls**: `bash: grep -n "\.call\|\.transfer\|\.send" *.sol` — check return values
8. **Events**: `bash: grep -n "emit\|event " *.sol` — state changes need events for off-chain monitoring
9. **Slither**: Run detectors above
10. **Edge cases**: Zero address inputs, empty arrays, max uint values

Severity rating: Critical (fund loss) > High (fund risk) > Medium (griefing) > Low (best practice) > Informational.
