# iTerm2: Arbitrary Code Execution via SSH Integration Escape Sequences

This directory contains the writeup, PoCs, and notes for the iTerm2 `cat readme.txt` conductor escape-sequence bug.

## Artifacts

- `blog.md`: Blog post draft, "MAD Bugs: Even `cat readme.txt` is not safe"
- `report.md`: Vulnerability report and original exploit summary
- `genpoc.py`: Original file-based PoC generator
- `genpoc2.py`: Rebuilt exploit derived from analyzing the patch
- `prompts.md`: Prompts used to reconstruct the exploit from the patch
- `poc`: original PoC

## Quick start

Turn iTerm2, and:

```sh
cd poc
cat readme.txt
```

You can also regenerate the PoC:

```sh
python3 genpoc.py
unzip poc.zip
cat readme.txt
```


## A note on the artifacts

The write-ups and PoCs in this series are AI-generated and human-verified. We keep human editing to a minimum so the artifacts document the current state of the art, which means we don't edit out hallucinations or slop. We do verify that the PoCs work. The blog posts are written by humans.
