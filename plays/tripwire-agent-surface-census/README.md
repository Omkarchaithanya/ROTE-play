# TRIPWIRE Agent Surface Census

This is the packaged Rote Play for Mobi's static AgentOps surface check.

It inspects local agent harness metadata, MCP configuration, credential-shaped files, listener metadata, recent git path metadata, and local Play metadata. It reports credential presence and risk state without printing secret values.

## Run

From WSL:

```bash
rote play run /mnt/c/Users/omkar/mobi/plays/tripwire-agent-surface-census/main.ts scope=all apply=false demo=true --output=human
```

After installing into local Rote discovery:

```bash
cd /tmp
rote play run tripwire-agent-surface-census scope=all apply=false demo=true --output=summary
```

## Expected Demo Output

The packaged demo fixture intentionally contains:

- a credential-shaped `.env` artifact
- MCP credential metadata represented as `PLACEHOLDER`
- a risky Play that claims read-only while containing write-like behavior

Expected result:

```text
TRIPWIRE S3 WRITE RISK findings=16
```

The policy decision is `CONDITIONAL` because S2 and S3 findings are present. The Play remains read-only; `revoke_stale` is declared but disabled.
