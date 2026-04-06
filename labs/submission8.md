# Lab 8 — Software Supply Chain Security: Signing, Verification, and Attestations

**Target:** `bkimminich/juice-shop:v19.0.0`

---

## Task 1 — Local Registry, Signing & Verification

### Commands

```bash
# Port 5000 on macOS is taken by AirTunes/AirPlay, using 5010 instead
docker run -d --restart=always -p 5010:5000 --name registry registry:3

docker tag bkimminich/juice-shop:v19.0.0 localhost:5010/juice-shop:v19.0.0
docker push localhost:5010/juice-shop:v19.0.0

# Get digest for the pushed image
DIGEST=$(curl -sI \
  -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
  http://localhost:5010/v2/juice-shop/manifests/v19.0.0 \
  | tr -d '\r' | awk -F': ' '/Docker-Content-Digest/ {print $2}')
REF="localhost:5010/juice-shop@${DIGEST}"
echo "Using digest ref: $REF" | tee labs/lab8/analysis/ref.txt
```

Pushed image digest:

```
localhost:5010/juice-shop@sha256:872efcc03cc16e8c4e2377202117a218be83aa1d05eb22297b248a325b400bd7
```

```bash
# Generate key pair
cd labs/lab8/signing
COSIGN_PASSWORD="" cosign generate-key-pair
cd -
```

Generated `cosign.key` (private, encrypted) and `cosign.pub` (public). Keys are NOT committed to the repo. `.gitignore` lists `labs/lab8/signing/cosign.key` and `labs/lab8/signing/cosign.pub` so a broad `git add labs/lab8/` cannot accidentally stage key material. The Cosign binary in the repo root is also ignored (`cosign`, `cosign-darwin-arm64`, etc.).

```bash
# cosign v3 deprecated --tlog-upload=false; need --use-signing-config=false to bypass
COSIGN_PASSWORD="" cosign sign --yes \
  --allow-insecure-registry \
  --tlog-upload=false \
  --use-signing-config=false \
  --key labs/lab8/signing/cosign.key \
  "$REF"

cosign verify \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  "$REF"
```

### Verification Output

```
Verification for localhost:5010/juice-shop@sha256:872efcc03cc16e8c4e2377202117a218be83aa1d05eb22297b248a325b400bd7 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"localhost:5010/juice-shop@sha256:872efcc..."},"image":{"docker-manifest-digest":"sha256:872efcc..."},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

### Tamper Demonstration

```bash
# Push a completely different image under the same tag
docker tag registry:3 localhost:5010/juice-shop:v19.0.0
docker push localhost:5010/juice-shop:v19.0.0

# Resolve the new (tampered) digest
DIGEST_AFTER=$(curl -sI \
  -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
  http://localhost:5010/v2/juice-shop/manifests/v19.0.0 \
  | tr -d '\r' | awk -F': ' '/Docker-Content-Digest/ {print $2}')
REF_AFTER="localhost:5010/juice-shop@${DIGEST_AFTER}"

# Verify tampered image -- FAILS
cosign verify --allow-insecure-registry --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub "$REF_AFTER"
# Error: no signatures found

# Verify ORIGINAL digest -- PASSES
cosign verify --allow-insecure-registry --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub "$REF"
# Verification for localhost:5010/juice-shop@sha256:872efcc... -- OK
```

### Analysis

Signing and tags: a tag like `v19.0.0` can be overwritten. Someone with push access can publish a different manifest under the same name, so `docker pull ...:v19.0.0` is not a fixed promise of content. Cosign signs the **digest** (hash of the manifest), which does not change unless the bytes change. Verify checks the signature against that digest; if the registry now points the tag at another image, the new digest has no signature and verify fails.

The JSON from `cosign verify` includes `docker-manifest-digest` so you can see exactly which manifest the signature was bound to (the "subject" in the claim).

`--tlog-upload=false` is deprecated in cosign v3; the docs push a signing-config without Rekor instead. Here I used `--use-signing-config=false` so the old flag still works for a local lab. For real use you would upload to Rekor (or equivalent) so others can audit signatures without trusting only your key.

Cosign may still print lines about the transparency log during verify; with `--insecure-ignore-tlog` you are not doing full online Rekor checks for this exercise.

---

## Task 2 — Attestations: SBOM & Provenance

### CycloneDX SBOM

Reusing the Syft SBOM from Lab 4, converted to CycloneDX format:

```bash
docker run --rm \
  -v "$(pwd)/labs/lab4/syft":/in:ro \
  -v "$(pwd)/labs/lab8/attest":/out \
  anchore/syft:latest \
  convert /in/juice-shop-syft-native.json -o cyclonedx-json=/out/juice-shop.cdx.json
```

Output: `labs/lab8/attest/juice-shop.cdx.json` (2.1 MB, 3532 components).

```bash
COSIGN_PASSWORD="" cosign attest --yes \
  --allow-insecure-registry \
  --tlog-upload=false \
  --use-signing-config=false \
  --key labs/lab8/signing/cosign.key \
  --predicate labs/lab8/attest/juice-shop.cdx.json \
  --type cyclonedx \
  "$REF"

cosign verify-attestation \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  --type cyclonedx \
  "$REF" | tee labs/lab8/attest/verify-sbom-attestation.txt
```

### SBOM Attestation Payload (jq inspection)

```bash
tail -n 1 labs/lab8/attest/verify-sbom-attestation.txt | \
  jq '{payloadType: .payloadType, predicateType: (.payload | @base64d | fromjson | .predicateType), componentCount: (.payload | @base64d | fromjson | .predicate.components | length)}'
```

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "predicateType": "https://cyclonedx.org/bom",
  "componentCount": 3532
}
```

### Provenance Attestation

```bash
BUILD_TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
cat > labs/lab8/attest/provenance.json << EOF
{
  "_type": "https://slsa.dev/provenance/v1",
  "buildType": "manual-local-demo",
  "builder": {"id": "student@local"},
  "invocation": {"parameters": {"image": "${REF}"}},
  "metadata": {"buildStartedOn": "${BUILD_TS}", "completeness": {"parameters": true}}
}
EOF

COSIGN_PASSWORD="" cosign attest --yes \
  --allow-insecure-registry \
  --tlog-upload=false \
  --use-signing-config=false \
  --key labs/lab8/signing/cosign.key \
  --predicate labs/lab8/attest/provenance.json \
  --type slsaprovenance \
  "$REF"

cosign verify-attestation \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  --type slsaprovenance \
  "$REF" | tee labs/lab8/attest/verify-provenance.txt
```

### Decoded Provenance Payload

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": {
    "_type": "https://in-toto.io/Statement/v0.1",
    "predicateType": "https://slsa.dev/provenance/v0.2",
    "subject": [
      {
        "name": "localhost:5010/juice-shop",
        "digest": { "sha256": "872efcc03cc16e8c4e2377202117a218be83aa1d05eb22297b248a325b400bd7" }
      }
    ],
    "predicate": {
      "builder": { "id": "student@local" },
      "buildType": "manual-local-demo",
      "invocation": {
        "parameters": { "image": "localhost:5010/juice-shop@sha256:872efcc..." }
      },
      "metadata": {
        "buildStartedOn": "2026-04-06T19:06:37Z",
        "completeness": { "parameters": true, "environment": false, "materials": false }
      }
    }
  }
}
```

### Analysis

A normal image signature only says: this key approved this digest. It does not list dependencies or how the image was built. An attestation is still a signature, but the signed payload is an in-toto statement with a **predicate** (extra JSON). For CycloneDX that predicate is the SBOM; for provenance it is build metadata.

The SBOM attestation here wraps ~3532 components (npm deps, OS packages, etc.) with versions and PURLs in the CycloneDX file. Whoever verifies with your public key knows the SBOM was not swapped in transit because it is inside the signed envelope. They can feed that SBOM into a scanner without re-running Syft on the image.

Provenance is the "who built this and when" part. My `provenance.json` used `_type` `https://slsa.dev/provenance/v1` because the lab template said so; after `cosign attest --type slsaprovenance`, the decoded statement shows `predicateType` `https://slsa.dev/provenance/v0.2` (cosign maps the input into the SLSA v0.2 predicate shape for the in-toto layer). So the envelope you see is v0.2 even though the file on disk said v1 in `_type`. In real CI you would fill in git commit, workflow id, and so on, which is useful for auditing and for figuring out which build to patch after an incident.

---

## Task 3 — Artifact (Blob/Tarball) Signing

### Commands

```bash
echo "sample content $(date -u)" > labs/lab8/artifacts/sample.txt
tar -czf labs/lab8/artifacts/sample.tar.gz -C labs/lab8/artifacts sample.txt

# cosign v3 new-bundle-format needs TUF trusted root for verify-blob;
# --output-signature gives a plain sig file that works with --insecure-ignore-tlog
COSIGN_PASSWORD="" cosign sign-blob \
  --yes \
  --tlog-upload=false \
  --use-signing-config=false \
  --key labs/lab8/signing/cosign.key \
  --output-signature labs/lab8/artifacts/sample.tar.gz.sig \
  labs/lab8/artifacts/sample.tar.gz

cosign verify-blob \
  --key labs/lab8/signing/cosign.pub \
  --signature labs/lab8/artifacts/sample.tar.gz.sig \
  --insecure-ignore-tlog \
  labs/lab8/artifacts/sample.tar.gz | tee labs/lab8/artifacts/verify-blob.txt
```

### Verification Output

```
Verified OK
```

### Analysis

Blob signing is for things that are not OCI images: release zips, helm charts, terraform bundles, config tarballs. If the file sits on S3 or a mirror, signing proves the bytes match what the publisher signed. In CI you can keep the public key and fail the pipeline if `verify-blob` does not say OK.

Image signing with cosign usually stores signatures in the **registry** as OCI artifacts linked to the image digest (not "another human-readable tag" like `myapp:signed`). Cosign finds them through the registry API. For a tarball you ship a separate `.sig` next to the file (or publish both to the same release page). Same idea (asymmetric crypto over a hash), different place the signature lives.
