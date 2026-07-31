# ida94_b1

IDA 9.4 analysis and patch package.

## Repository contents

- [`kg_patch/`](kg_patch/README): macOS ARM64 patch helper, license material, and x64 comparison samples.
- [`misc/`](misc/): auxiliary 9.4 artifacts.
- `SHA256SUMS`: hashes for every archived artifact and repository file.

The six IDA installer packages exceed GitHub's 100 MiB Git-file limit. They are preserved as assets of the private GitHub Release **`v9.4-installers`**, rather than being omitted.

## macOS Apple Silicon

```zsh
cd kg_patch
python3 patch_ida94_armmac.py \
  --app "/Applications/IDA Professional 9.4.app" \
  --in-place --apply --generate-license --sign
```

See [`kg_patch/README`](kg_patch/README) for the full workflow.
