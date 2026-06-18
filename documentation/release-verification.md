# Release Verification

E-Navigator release artifacts are published from `v*` tag builds and signed with
keyless Cosign through GitHub OIDC.

Set the release tag once:

```bash
export VERSION=v0.1.0
export REPO=guaracloud/e-navigator
```

## Download Release Assets

```bash
mkdir -p "e-navigator-${VERSION}"
gh release download "$VERSION" --repo "$REPO" --dir "e-navigator-${VERSION}"
cd "e-navigator-${VERSION}"
```

## Verify Checksums

```bash
for sum in *.sha256; do
  sha256sum -c "$sum"
done
```

On macOS, use `shasum -a 256 -c <file>.sha256` if GNU `sha256sum` is not
installed.

## Verify Blob Signatures

```bash
for sig in *.sig; do
  artifact="${sig%.sig}"
  cosign verify-blob "$artifact" \
    --signature "$sig" \
    --certificate "${artifact}.pem" \
    --certificate-identity-regexp '^https://github\.com/guaracloud/e-navigator/' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
done
```

## Verify The Container Image

Read the exact image reference from `release-manifest.json`:

```bash
image_ref="$(jq -r '.images[0].reference' release-manifest.json)"

cosign verify "$image_ref" \
  --certificate-identity-regexp '^https://github\.com/guaracloud/e-navigator/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

Use the digest-pinned reference from the manifest in production values.

## Verify SBOMs

Release SBOMs are SPDX JSON:

```bash
for sbom in *.spdx.json; do
  jq -e '.spdxVersion and .packages' "$sbom" >/dev/null
done
```

## Verify The Helm Chart

```bash
helm pull oci://ghcr.io/guaracloud/charts/e-navigator --version "${VERSION#v}"
sha256sum -c "e-navigator-${VERSION#v}.tgz.sha256"
```

The chart digest is recorded in `release-manifest.json` under
`helm_chart.digest`.

## Verify The Release Manifest

```bash
cosign verify-blob release-manifest.json \
  --signature release-manifest.json.sig \
  --certificate release-manifest.json.pem \
  --certificate-identity-regexp '^https://github\.com/guaracloud/e-navigator/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'

jq -e '.schema == "e-navigator.release-manifest/v1"' release-manifest.json
```
