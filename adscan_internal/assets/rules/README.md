# Hashcat rule files

Rule files (`-r`) mangle each wordlist candidate into many variants during a
hashcat attack. ADscan resolves them through
`adscan_internal.cli.cracking.resolve_rules_path(name)`, which searches:

1. **This bundled directory** (`adscan_internal/assets/rules/`) — ships small,
   always-available rules.
2. **The managed rules directory** under the ADscan home
   (`~/.adscan/wordlists/rules/` on the host ↔ `/opt/adscan/wordlists/rules/`
   in the container) — where large rules are placed by the operator or a
   wordlist installer.

## Bundled

- `best64.rule` — the canonical hashcat *best64* rule set (~77 rules). Cheap
  and safe to layer on top of any wordlist, including the large bundled lists,
  and mandatory for the slower AES Kerberos modes.
- `OneRuleToRuleThemStill-10k.rule` — the frequency-ordered 10,000-rule prefix
  of `OneRuleToRuleThemStill.rule`, committed as the effort-ladder's
  *intermediate* rung between `best64` (77) and the full OneRule (48,414). It
  lets the time-budgeted `thorough` tier scale into the 94M audit base on a mid
  GPU (or downgrade to it from the full set) instead of collapsing straight to
  `best64`. Small (~81 KB) and always available. See
  `adscan_internal/services/cracking_wordlist_policy.py` `_RULE_LADDER`.

## Managed (not bundled — resolved from `~/.adscan/wordlists/rules/`)

- `OneRuleToRuleThemStill.rule` — the large community rule set (~49.5k rules,
  ~1.6 MB). Too large to commit; it is the effort-ladder's `thorough` **top
  rung** (index 3) — used when the measured hardware can traverse it inside the
  tier's time budget, and falls back to the bundled
  `OneRuleToRuleThemStill-10k.rule` (then `best64.rule`) when it is not present.
  Install it by dropping the file into
  `~/.adscan/wordlists/rules/OneRuleToRuleThemStill.rule`. Upstream:
  https://github.com/stealthsploit/OneRuleToRuleThemStill
