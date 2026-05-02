# Demo Model — `tiny-toy-classifier`

A synthetic model directory used by the AI Security Portfolio's
supply-chain scanner (Project 6) to demonstrate end-to-end scanning
without distributing a real model.

## Intended use

For framework-demo purposes only. This directory is **not a real
trained model** — the weight file is a deliberately small, safe pickle
containing a Python list. The directory exists to exercise:

  - The provenance scanner's required-files check.
  - The dependencies scanner's risky-package detection.
  - The SBOM generator's per-file enumeration.

## Limitations

Not trained. Not evaluated. Not licensed for downstream use beyond
this scanner demonstration.
