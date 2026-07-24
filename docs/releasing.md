# Releasing Automic Vault

Automic Vault releases are built and published only by
`.github/workflows/release.yml`. Do not publish a DMG from a local checkout and
never replace an existing release asset. A correction is a new patch release.

The workflow runs from `main`, builds the reviewed commit, signs and notarizes
the app, staples the notarization ticket, creates SHA-256 checksums and an SPDX
SBOM, attests the final DMG, publishes an immutable GitHub release, then copies
those verified bytes to the website bucket. Third-party Actions, the Rust
toolchain, `create-dmg`, and the Syft SBOM generator are pinned.

## One-time GitHub setup

Create a GitHub Actions environment named `release`. Protect it with required
reviewers and prevent non-`main` deployment branches if the repository plan
supports those controls.

Enable immutable releases:

```sh
gh api \
  --method PUT \
  -H "X-GitHub-Api-Version: 2026-03-10" \
  repos/automic-vault/automic-vault/immutable-releases
```

After that succeeds, record the one-time assertion on the protected
environment:

```sh
gh variable set IMMUTABLE_RELEASES_ENABLED \
  --repo automic-vault/automic-vault \
  --env release \
  --body true
```

The built-in Actions token deliberately has no repository-administration
permission, so the workflow checks this assertion before building. Immediately
after publication it verifies through the release API that GitHub actually
marked the release immutable. Do not set the variable before enabling the
repository setting.

### Environment secrets

Add these secrets to the `release` environment:

| Name | Value |
| --- | --- |
| `MACOS_DEVELOPER_ID_P12_BASE64` | Base64 of the Developer ID Application certificate and private key exported as a password-protected `.p12` |
| `MACOS_DEVELOPER_ID_P12_PASSWORD` | Password chosen while exporting that `.p12` |
| `APPLE_PASSWORD` | App-specific password for that Apple ID, not the normal account password |

Set them interactively so values do not enter shell history:

```sh
gh secret set SECRET_NAME \
  --repo automic-vault/automic-vault \
  --env release
```

To prepare the binary values on macOS:

```sh
base64 <DeveloperIDApplication.p12 | pbcopy
```

Paste that value into `MACOS_DEVELOPER_ID_P12_BASE64`.

### Environment variables

The provisioning profile, Apple account name and team identifier, PostHog
project key, and AWS role ARN are not secrets. The profile is embedded in the
distributed app, the PostHog key is embedded in its `Info.plist`, and the
remaining values are identifiers.

Add them as non-secret variables on the `release` environment:

```sh
base64 <Automic_Vault_Developer_ID.provisionprofile |
  gh variable set MACOS_PROVISIONING_PROFILE_BASE64 \
    --repo automic-vault/automic-vault \
    --env release

gh variable set APPLE_USERNAME \
  --repo automic-vault/automic-vault \
  --env release \
  --body APPLE_ID_EMAIL

gh variable set APPLE_TEAM_ID \
  --repo automic-vault/automic-vault \
  --env release \
  --body TEAM_ID

gh variable set POSTHOG_API_KEY \
  --repo automic-vault/automic-vault \
  --env release \
  --body PROJECT_KEY

gh variable set AWS_ROLE_ARN \
  --repo automic-vault/automic-vault \
  --env release \
  --body arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME
```

Then add the ordinary deployment configuration:

```sh
gh variable set AWS_REGION \
  --repo automic-vault/automic-vault \
  --env release \
  --body us-east-1

gh variable set AWS_S3_BUCKET \
  --repo automic-vault/automic-vault \
  --env release \
  --body automicvault.com
```

The AWS role needs only:

- `s3:PutObject` and `s3:GetObject` for
  `arn:aws:s3:::automicvault.com/Automic Vault.dmg`;
- `cloudfront:ListDistributions`;
- `cloudfront:CreateInvalidation` and `cloudfront:GetInvalidation` for the
  website distribution.

Its OIDC trust policy should restrict `sub` to:

```text
repo:automic-vault/automic-vault:environment:release
```

and require the `sts.amazonaws.com` audience.

## Publish a release

First merge a reviewed version bump for `Cargo.toml` and `Cargo.lock` to `main`.
The workflow never edits or commits version metadata.

Then dispatch the workflow from `main`:

```sh
gh workflow run release.yml \
  --repo automic-vault/automic-vault \
  --ref main \
  -f version=X.Y.Z
```

The run fails if the version differs from `Cargo.toml`, the tag or release
already exists, the checkout is not the dispatched commit, required secrets are
missing, or immutable releases are disabled.

## Verify

Download the release assets and verify the final DMG:

```sh
gh attestation verify Automic-Vault-X.Y.Z.dmg \
  --repo automic-vault/automic-vault \
  --signer-workflow \
    automic-vault/automic-vault/.github/workflows/release.yml

shasum -a 256 -c SHA256SUMS
xcrun stapler validate Automic-Vault-X.Y.Z.dmg
```

The release page must show the release as immutable. The website job also
checks the GitHub asset digest, verifies build provenance, uploads that same
DMG to S3 with an S3 SHA-256 checksum, verifies the stored checksum, and waits
for CloudFront invalidation.

If the website job fails after the GitHub release is published, rerun only the
failed job. Do not delete or replace the immutable release.
