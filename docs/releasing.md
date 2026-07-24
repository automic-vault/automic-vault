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
| `MACOS_PROVISIONING_PROFILE_BASE64` | Base64 of the Developer ID provisioning profile used by the menu bar app |
| `APPLE_USERNAME` | Apple ID used for notarization |
| `APPLE_PASSWORD` | App-specific password for that Apple ID, not the normal account password |
| `APPLE_TEAM_ID` | Apple Developer team identifier |
| `POSTHOG_API_KEY` | Production PostHog project key embedded in the distributed app |
| `AWS_ROLE_ARN` | IAM role assumed through GitHub OIDC to publish the website DMG |

Set them interactively so values do not enter shell history:

```sh
gh secret set SECRET_NAME \
  --repo automic-vault/automic-vault \
  --env release
```

To prepare the binary values on macOS:

```sh
base64 <DeveloperIDApplication.p12 | pbcopy
base64 <Automic_Vault_Developer_ID.provisionprofile | pbcopy
```

Paste the first value into `MACOS_DEVELOPER_ID_P12_BASE64` and the second into
`MACOS_PROVISIONING_PROFILE_BASE64`.

### Environment variables

Add these non-secret variables to the `release` environment:

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
