# MAD Bugs: Vim vs. Emacs vs. Claude

Two unrelated RCE classes found by Claude in the editor wars: a Vim modeline RCE and multiple file-open RCE vectors in GNU Emacs.

| File | What |
|---|---|
| [`vim.md`](vim.md) | Vim tabpanel modeline RCE (Vim < 9.2.0272) |
| [`Emacs.md`](Emacs.md) | GNU Emacs: multiple RCE vectors on file open |
| [`emacs-poc.tgz`](emacs-poc.tgz) | Emacs PoC archive |
| [`vim-claude-prompts.txt`](vim-claude-prompts.txt) | Prompt log (Vim) |
| [`emacs-claude-prompts.txt`](emacs-claude-prompts.txt) | Prompt log (Emacs) |

## A note on the artifacts

The write-ups and PoCs in this series are AI-generated and human-verified. We keep human editing to a minimum so the artifacts document the current state of the art, which means we don't edit out hallucinations or slop. We do verify that the PoCs work. The blog posts are written by humans.
