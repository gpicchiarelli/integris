# Evidence artifacts

Campaign manifests are produced by:

```sh
go run ./cmd/integris-evidence -root .
```

Each `EVD-*-campaign.json` records revision, platform, commands, stdout digests,
and residual gaps. Sibling `.sha256` files digest the JSON body.

**Status rules**

- A file here is an artifact, not automatic acceptance.
- Only records with `status: produced` in `assurance/evidence.json` are claimed.
- IC-1 campaigns may keep `planned` while residual platform/review gaps remain.
