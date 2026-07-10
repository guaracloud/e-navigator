# Release Process

E-Navigator releases are cut from the current `main` commit and published by a
tag-triggered GitHub Actions workflow. The workflow builds and signs the image
and chart, creates a draft GitHub Release, verifies every published artifact,
and publishes the draft only after verification succeeds.

## Release Contract

One SemVer value must agree across:

- `[workspace.package].version` and every Cargo workspace package;
- `e-navigator --version`;
- Helm `version` and `appVersion`;
- the default Helm and raw-manifest image tag;
- README, website, install, and verification examples;
- the `CHANGELOG.md` release section;
- the `vX.Y.Z` or `vX.Y.Z-prerelease` Git tag.

All workspace crates are intentionally `publish = false`. The supported
distribution surfaces are the signed OCI image, OCI Helm chart, and attached
verification artifacts.

## Prepare A Version

Start from an up-to-date branch created from `main`:

```bash
python3 scripts/release.py prepare 0.2.0-rc.1
```

Add the matching changelog section, reconcile public capability claims, and
then run:

```bash
python3 scripts/release.py check 0.2.0-rc.1
scripts/quality.sh
```

The preparation command updates version-bearing Cargo, lockfile, chart,
manifest, documentation, and website surfaces. It deliberately does not write
release notes: the changelog remains a reviewed human statement.

Land the release commit through a pull request. Do not tag until every required
check for that exact `main` commit succeeds.

## Release Candidates

The first tag in a release line should be a candidate such as
`v0.2.0-rc.1`. Candidate releases are marked as GitHub prereleases, publish
`v0.2.0-rc.1` and `0.2.0-rc.1` image tags, and never move `latest`.

Create an annotated tag on the verified `main` commit and push only that tag.
The release workflow then runs without further mutation of the source tree;
the image and attached release files are signed keylessly through GitHub OIDC.

Validate the published candidate from a clean directory and install its OCI
chart in a disposable local or homelab namespace. If a candidate fails, fix the
cause on `main` and cut `rc.2`. Never move, delete, or reuse a published tag.

## Stable Releases

After the candidate passes:

1. Run `python3 scripts/release.py prepare X.Y.Z`.
2. Add the stable changelog section and update status copy.
3. Run the release check and full quality gate.
4. Land the exact release commit on `main` and wait for required checks.
5. Create and push the annotated `vX.Y.Z` tag.

Stable releases publish `vX.Y.Z` and `X.Y.Z` image tags. The workflow promotes
`latest` to the verified image digest only after all signatures, checksums,
SBOMs, image platforms, chart pulls, image aliases, and synthetic image runs
pass.

## Published Artifacts

Each release contains:

- a `linux/amd64` and `linux/arm64` OCI image index;
- an OCI Helm chart;
- image, chart, and source SPDX JSON SBOMs;
- SHA-256 files, Cosign signatures, and signing certificates;
- `release-manifest.json` with the commit, image digest, chart digest, aliases,
  and provenance method.

The GitHub Release stays in draft state if verification fails. Versioned OCI
artifacts may already exist after such a failure; investigate them, fix forward,
and use a new prerelease version rather than overwriting a published contract.

## Repairing Image Aliases

`.github/workflows/publish-image-aliases.yml` can recreate a missing SemVer
alias from an existing signed `vX.Y.Z` digest. It verifies that the alias points
to the identical digest. Moving `latest` is an explicit stable-only input.
