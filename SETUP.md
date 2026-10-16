# Setup & operations reference

Full configuration, notifications, and troubleshooting for the AI SOC analyst lab.
For the project overview and write-up, see [README.md](README.md).

## Requirements

- An Ubuntu host (bare metal or VM) with Docker Engine + the compose plugin, and your
  user in the `docker` group.
- ~4 GB RAM free (the Wazuh indexer alone wants 1–2 GB).
- An Anthropic API key.

On a Linux host the Wazuh indexer needs `vm.max_map_count=262144`; `scripts/setup.sh`
sets this for you.

## First run

```bash
./scripts/setup.sh                 # clone Wazuh, generate certs, bump vm.max_map_count, make .env
nano .env                          # add ANTHROPIC_API_KEY
docker compose up -d --build       # ~2.5 GB of Wazuh images on first pull
docker compose ps                  # all six services running; indexer may be "starting" for ~2 min
```

Dashboard: `https://<host-ip>/` → admin / SecretPassword (self-signed cert).

## Configuration (`.env`)

| Key | Meaning |
|---|---|
| `ANTHROPIC_API_KEY` | Required. |
| `CLAUDE_MODEL` | Default `claude-opus-5-5`. |
| `CLAUDE_EFFORT` | `low`→`max`. Higher = deeper reasoning, more tokens. Default `medium`. |
| `MIN_RULE_LEVEL` | Only triage Wazuh alerts ≥ this level (0–15). Default `7`. |
| `POLL_INTERVAL_SECONDS` | How often to poll the indexer. Default `30`. |
| `MAX_TRIAGES_PER_HOUR` | Hard cap on Claude calls/hour. Default `20`. |
| `ABUSEIPDB_API_KEY` / `VIRUSTOTAL_API_KEY` | Optional enrichment; blank = skipped. |
| `NOTIFY_WEBHOOK_URL` | Optional Slack/Discord incoming webhook. |
| `NOTIFY_SEVERITIES` | Which severities to notify on. Default `critical,high`. |

## Slack / Discord notifications

Set `NOTIFY_WEBHOOK_URL` in `.env`, then `docker compose up -d --force-recreate ai-analyst`.

- **Slack**: api.slack.com/apps → Create App (Blank) → add the `incoming-webhook`
  scope → Install to Workspace → pick a channel → copy the webhook URL.
- **Discord**: Server Settings → Integrations → Webhooks → New Webhook → copy URL.

Quick test (posts straight to the webhook):
```bash
curl -s -X POST -H 'Content-type: application/json' \
  --data '{"text":"test from the AI SOC lab"}' \
  "$(grep '^NOTIFY_WEBHOOK_URL=' .env | cut -d= -f2-)"; echo   # prints "ok"
```

## Offline triage test (no stack needed)

```bash
cd analyst && pip install -r requirements.txt && cd ..
export ANTHROPIC_API_KEY=sk-ant-...
python scripts/test_triage.py samples/bruteforce_alerts.json
```
Without the key it still exercises correlation + report rendering with a canned verdict.

## Troubleshooting

**No alerts being triaged / analyst log quiet after an attack.** Check the agent is
connected: `docker compose exec wazuh.manager /var/ossec/bin/agent_control -l` should
show `victim-linux ... Active`.

**Agent shows `Disconnected` / `Duplicate agent name` after a rebuild.** The new
container has no enrollment key and re-enrolls, but the manager still holds the old
registration under the same name (Wazuh only auto-overrides a stale agent after it has
been disconnected ~1h). Remove it and restart:
```bash
docker compose exec wazuh.manager /var/ossec/bin/manage_agents -r <old_id>   # e.g. 001
docker compose restart victim
```

**auth.log is empty / SSH attacks produce no detections.** This was the main build
hurdle — three independent causes, all fixed in the image, documented here so the
pattern is clear:
- rsyslog runs as the `syslog` user and can't write a `root`-owned `auth.log`
  (entrypoint now creates it with the right owner).
- sshd must start *after* rsyslog so `/dev/log` exists.
- Ubuntu's default ISO8601 timestamp isn't parsed by Wazuh's decoder — the image sets
  `RSYSLOG_TraditionalFileFormat` (`victim/rsyslog-traditional.conf`).
If logs exist but the dashboard shows 0 auth failures and no `sshd` rule group, it's a
decode problem, not a collection problem — check the timestamp format in `auth.log`.

**Repeated brute-force runs stop producing alerts.** Wazuh's brute-force rules
(5712 / 5763 / 40112) are frequency-based and won't re-fire on rapid back-to-back runs.
Wait ~5 minutes of no SSH activity, or test on a fresh `docker compose down -v && up`.

**Make the demo notify on every run.** Temporarily set `MIN_RULE_LEVEL=5` and
`NOTIFY_SEVERITIES=critical,high,medium,low`, recreate the analyst. Revert to `7` /
`critical,high` for low-noise operation.

## Teardown

```bash
docker compose down            # stop, keep data
docker compose down -v         # stop and delete all Wazuh data volumes
```
