#!/usr/bin/env python3
"""Policy Engine — security rules for tool calls.
Modelled after Claude Code's permission system (allow, deny, ask).
"""

import re
import os
import copy
import json
import shlex
import logging
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

# The bash deny-list is a heuristic, not a security boundary: bash is
# Turing-complete and pattern matching is bypassable. See SECURITY.md.

# Denied as the literal first token of a parsed command; the regex pass still runs.
_ARGV0_DENY = {
    # Filesystem / hardware destruction
    "mkfs", "dd", "shred", "hdparm", "blkdiscard", "wipefs",
    # System control (keep in sync with the regex above for consistency)
    "shutdown", "reboot", "halt", "poweroff", "init",
    # Scanners — require plugin opt-in
    "nmap", "masscan", "nikto", "sqlmap", "thehoneyharvester", "theharvester",
    "dirb", "gobuster", "hydra", "patator", "medusa",
    # curl and wget are deliberately absent: too many legitimate uses, and the
    # regex pass catches pipe-to-shell.
    "nc", "ncat", "socat",
    # Also caught by the regex, but argv[0] gives a clearer denial reason.
    "env", "printenv",
}

def _argv0_check(cmd: str) -> Optional[str]:
    """Parses the command with shlex and applies argv-level denies.

    Catches what the regex misses by reading the program name after tokenization.
    Does not expand $(…) or recurse into `bash -c`; unparseable input falls
    through to the regex layer. Returns a reason on deny, None otherwise.
    """
    try:
        tokens = shlex.split(cmd, posix=True)
    except ValueError as e:
        # Unparseable input falls through to the regex pass, and records that the
        # parse was abandoned.
        log.debug("argv0_check: shlex.split failed on %r: %s", cmd[:120], e)
        return None
    if not tokens:
        return None
    prog = os.path.basename(tokens[0]).lower()
    # Normalise obvious obfuscation: strip leading backslash (\rm → rm).
    if prog.startswith("\\"):
        prog = prog[1:]
    if prog in _ARGV0_DENY:
        return f"argv[0]='{prog}' is on the program denylist"
    # The regex only sees the exact form, so deny rm whenever a positional
    # argument is / or a top-level directory. Ordinary deletes are unaffected.
    if prog == "rm":
        args_tail = tokens[1:]
        if "--" in args_tail:
            args_tail = args_tail[args_tail.index("--") + 1:]
        else:
            args_tail = [a for a in args_tail if not a.startswith("-")]
        for a in args_tail:
            if a == "/" or re.fullmatch(r"/(bin|boot|etc|home|lib\w*|opt|root|sbin|srv|usr|var)/?", a):
                return f"rm targets a top-level directory ({a!r})"
    return None

# Loaded if policy.json is missing.

DEFAULT_POLICIES = {
    # DENY protects hardware and critical data; ASK covers reversible but
    # consequential actions. Everything else is ALLOW. Table in README.md.
    "bash": {
        "deny": [
            r"mkfs\.",                          # format filesystem
            r"dd\s+.*of=/dev/",                 # raw write to device
            r">\s*/dev/sd",                     # redirect to raw device
            r">\s*/dev/nvme",                   # redirect to nvme device
            r"hdparm\s+.*--security-erase",     # disk erase
            r"blkdiscard",                      # discard block device
            r"wipefs",                          # wipe filesystem signatures

            r"rm\s+(-[a-zA-Z]*f|-[a-zA-Z]*r|--force|--recursive)\s+/",  # rm -rf / or /anything
            r"rm\s+-[a-zA-Z]*\s+/",              # rm with any flags targeting /
            # Fork bomb. The parentheses and braces are regex metacharacters and must be escaped.
            r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
            r"shutdown",
            r"reboot",
            r"init\s+[06]",
            r"systemctl\s+(stop|disable|mask)\s+(sshd|NetworkManager|systemd)",

            r"chmod\s+777\s+/",                 # world-writable root
            r"chmod\s+\+s",                     # setuid
            r"chown\s+root",                    # ownership escalation
            r"curl.*\|\s*(bash|sh|zsh)",        # pipe to shell
            r"wget.*\|\s*(bash|sh|zsh)",
            r"\beval\b",                         # eval injection (all forms)

            r"cat.*/etc/shadow",
            r"cat.*\.ssh/id_",
            r"cat.*\.gnupg/",
            # Denies the literal forms only; `printf "%s" "$FOO"` still gets through.
            r"^\s*env(\s|$)",
            r"^\s*printenv(\s|$)",
            # Only `export -p` dumps the environment; plain `export PATH=...` is ordinary.
            r"^\s*export\s+-p\b",
            r"\$\{?ANTHROPIC_API_KEY\}?",
            r"\$\{?WEB_TOKEN\}?",
            # Reverse-shell one-liners commonly used post-injection.
            r"\bnc\b.*\s-e\b",
            r"\bncat\b.*\s-e\b",
            r"/dev/tcp/",                      # bash TCP redirect
            r"bash\s+-i\s+>&\s*/dev/tcp",
            # base64 / xxd piped to shell — classic obfuscated RCE.
            r"base64\s+-d\b.*\|\s*(bash|sh|zsh)",
            r"xxd\s+-r.*\|\s*(bash|sh|zsh)",

            r"\bnmap\b",
            r"\bnikto\b",
            r"\bsqlmap\b",
            r"\btheHarvester\b",
            r"\bmasscan\b",
            r"\bdirb\b",
            r"\bgobuster\b",
            r"\bhydra\b",
        ],
        "ask": [
            # sudoedit needs its own pattern: \bsudo\b misses it, there being no word
            # boundary between "sudo" and "edit".
            r"\bsudo(?:edit)?\b",
            r"\bapt(-get)?\s+install\b",
            # Same operation as `pip install`, without the literal token.
            r"\bpip3?\s+install\b",
            r"\bpython3?\s+-m\s+pip\s+install\b",
            # A leading space is required, or `-f\b` also matches a branch name ending in -f.
            r"git\s+push\b.*(?:--force\b|(?<!\S)-f\b)",
            # Anchored to a command position, or \bkill\b matches any line mentioning the
            # word while missing pkill and killall.
            r"(?:^|[;&|]\s*)(?:sudo\s+)?p?kill(?:all)?\b",
        ],
        "allow": [
            r".*",  # everything not denied
        ]
    },
    # Writing to these gives persistent execution: a later shell launch, cron tick
    # or systemd unit runs the file. One list, shared by write_file and edit_file.
    "_PERSISTENCE_DENY": [
        # config, rc and env give persistence through ProxyCommand or LocalCommand.
        r"\.ssh/",
        r"\.gnupg/",
        # Shell init files (bash, zsh, sh, fish) and their .d/ drop-ins.
        r"\.bashrc$", r"\.bash_profile$", r"\.bash_login$", r"\.bash_logout$",
        r"\.bashrc\.d/",
        r"\.zshrc$", r"\.zshenv$", r"\.zprofile$", r"\.zlogin$",
        r"\.zshrc\.d/",
        r"\.profile$",
        r"\.inputrc$",
        r"\.config/fish/", r"(^|/)fish/config\.fish$",
        # X11 / Wayland / desktop-session init files.
        r"\.xinitrc$", r"\.xsession$", r"\.xsessionrc$", r"\.xprofile$",
        # XDG-style triggers: systemd user units, autostart, env.d, apps.
        r"\.config/systemd/user/",
        r"\.config/autostart/",
        r"\.config/environment\.d/",
        r"\.local/share/applications/.*\.desktop$",
        # Cron.
        r"(^|/)crontab$",
        r"/var/spool/cron/",
        r"/etc/cron",
        # Python site-packages .pth — runs on every python invocation.
        r"site-packages/.*\.pth$",
        # A crafted .gitconfig [alias] runs on the next `git <alias>`, like a hook.
        r"\.git/hooks/",
        r"\.gitconfig$", r"\.config/git/config$",
        # Editor startup files — vim/neovim run code on first invocation.
        r"\.vimrc$", r"\.gvimrc$",
        r"\.config/nvim/init\.(vim|lua)$",
        # These alter what gets imported or fetched on the next pip, npm or python run.
        r"\.config/pip/pip\.conf$", r"(^|/)pip\.conf$", r"\.pip/pip\.conf$",
        r"\.npmrc$", r"\.pypirc$",
        # Loaded at startup, so a write here runs on the next start. A non-word
        # lookahead rather than `$`, so the path is matched inside a bash command too.
        r"(^|/)plugins/.*\.py(?!\w)",
        # Every extension the loader picks up is equally persistent: .pth loads at
        # interpreter start, .so as an extension, .pyc can pre-empt the source.
        r"(^|/)plugins/.*\.(pth|so|pyc)(?!\w)",
        # A .pth file runs wherever site-packages imports it, not only inside plugins/.
        r"(^|/)[^/]+\.pth(?!\w)",
    ],

    # One list for every tool, so no single tool becomes the way past the others.
    # Live credentials are off-limits to reads and writes alike.
    "_CREDENTIAL_DENY": [
        # The trailing (/|$) denies listing the directory too: the names alone are a lead.
        r"\.ssh(/|$)",
        r"\.gnupg(/|$)",
        r"(^|/)shadow$",
        r"\.env($|\.)",
        r"\.envrc$",
        r"\.aws(/|$)",
        r"\.azure(/|$)",
        r"\.gcloud(/|$)",
        r"\.kube/config",
        r"\.docker/config\.json",
        r"\.netrc$",
        r"\.git-credentials$",
        r"\.config/.*(token|credentials|secret|apikey|api_key)",
        # npmrc and pypirc hold live tokens, so reads are denied as well as writes.
        r"\.npmrc$", r"\.pypirc$",
        # The session store holds prior tool output, so reading it goes around the
        # read_file denies.
        r"(^|/)\.cortex/sessions(/|$)",
        # Filename-level patterns: the directory-only ones above miss a glob like
        # **/id_rsa under a benign parent.
        r"(^|/)id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$",
        r"(^|/)authorized_keys$",
        r"(^|/)known_hosts$",
        r"(^|/)credentials$",
        r"(^|/)\.env(\..+)?$",
        r"(^|/)shadow$",
    ],

    # History files hold typed passwords and tokens, so reads are blocked even
    # though writing them is harmless.
    "_HISTORY_DENY": [
        r"\.bash_history$", r"\.zsh_history$", r"\.python_history$",
        r"\.lesshst$", r"\.mysql_history$", r"\.psql_history$",
        r"\.node_repl_history$",
    ],

    # System paths the agent must never overwrite, root or not.
    "_SYSTEM_DIRS_DENY": [
        r"^/boot/",
        r"^/usr/",
        r"^/bin/",
        r"^/sbin/",
        r"^/etc/",
    ],

    # The three underscore-prefixed keys above are merged into the real tool rules
    # by _expand_shared_lists(); they are not tool names.
    "write_file": {
        "deny": [
            # filled in by _expand_shared_lists() from the three lists above
        ],
        "ask": [],
        "allow": [r".*"],
    },
    "read_file": {
        "deny": [
            # filled in by _expand_shared_lists()
        ],
        "allow": [r".*"],
    },
    "list_dir": {
        "deny": [
            # Credential directories are not enumerable either: the profile names are a lead.
        ],
        "allow": [r".*"],
    },
    "cs_note": {"allow": [r".*"]},
    "cs_task": {"allow": [r".*"]},
    "cs_briefing": {"allow": [r".*"]},
    "grep_search": {
        "deny": [
            # Filled in by _expand_shared_lists(), or grep_search goes around read_file.
        ],
        "allow": [r".*"],
    },
    "edit_file": {
        "deny": [
            # filled in by _expand_shared_lists()
        ],
        "allow": [
            r"^" + str(Path.home()) + r"/",
            r"^/tmp/",
        ],
    },
    "glob_find": {
        "deny": [
            # Filled in by _expand_shared_lists(), or `**/id_rsa` enumerates credential
            # filenames without ever calling read_file.
        ],
        "allow": [".*"]
    },
    # Plugin tools have no built-in rules, so check() falls back to ASK. Add rules
    # here as "my_plugin_tool": {"deny": [...], "ask": [...], "allow": [...]}.
}


def _expand_shared_lists(policies: dict) -> dict:
    """Move the underscore-prefixed shared lists into the real tool rules.

    Keeps the source readable (one canonical _PERSISTENCE_DENY /
    _CREDENTIAL_DENY / _HISTORY_DENY / _SYSTEM_DIRS_DENY) and removes the
    copy-paste drift class that tripped up v1.0.5 — where write_file and
    edit_file fell out of sync and one of them missed a cloud-cred deny
    the other had.
    """
    persistence = policies.pop("_PERSISTENCE_DENY", [])
    credential  = policies.pop("_CREDENTIAL_DENY", [])
    history     = policies.pop("_HISTORY_DENY", [])
    system_dirs = policies.pop("_SYSTEM_DIRS_DENY", [])

    def _merge_unique(*lists):
        """Order-preserving dedup, so re-expanding an already-expanded policy
        does not double every deny."""
        seen = {}
        for lst in lists:
            for item in lst:
                if item not in seen:
                    seen[item] = None
        return list(seen.keys())

    # Write paths: persistence + credentials (poisoning) + system dirs.
    for tool in ("write_file", "edit_file"):
        rules = policies.setdefault(tool, {"deny": [], "allow": [r".*"]})
        rules["deny"] = _merge_unique(system_dirs, persistence, credential, rules.get("deny", []))

    # Credentials and history. Persistence files are config rather than secrets,
    # so they stay readable.
    rf = policies.setdefault("read_file", {"deny": [], "allow": [r".*"]})
    rf["deny"] = _merge_unique(credential, history, rf.get("deny", []))

    # Search and enumeration must not become a read_file bypass: an unrestricted
    # search over the same path reaches what read_file denies.
    for tool in ("grep_search", "list_dir", "glob_find"):
        rules = policies.setdefault(tool, {"deny": [], "allow": [r".*"]})
        rules["deny"] = _merge_unique(credential, history, rules.get("deny", []))

    # Unobfuscated writes to persistence paths go through the same gate as
    # write_file. Obfuscated forms remain a matter for the heuristic above.
    bash_rules = policies.setdefault("bash", {"deny": [], "allow": [r".*"]})
    bash_rules["deny"] = _merge_unique(
        bash_rules.get("deny", []),
        # These paths appear verbatim in a command line, so the same patterns apply.
        persistence,
        # Bash must not be the way around read_file: `cat ~/.ssh/id_rsa` reaches the
        # same file.
        credential,
    )

    return policies


# Copied before expansion: _expand_shared_lists pops these keys, and
# _merge_policies needs them to re-expand a custom policy.json.
SHARED_DEFAULTS = {
    k: list(DEFAULT_POLICIES.get(k, []))
    for k in ("_CREDENTIAL_DENY", "_PERSISTENCE_DENY",
              "_HISTORY_DENY", "_SYSTEM_DIRS_DENY")
}

DEFAULT_POLICIES = _expand_shared_lists(DEFAULT_POLICIES)


class PolicyDecision:
    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"


def _normalize_path(raw: str) -> str:
    """Resolves traversal, symlinks and relative paths to a canonical absolute form
    before the policy check.

    Without it both bypasses work: /tmp/../etc/cron.d/evil never matches ^/etc/,
    and a symlink lets policy judge a benign path while the OS dereferences to the
    sensitive one. strict=False normalises paths that do not exist yet.
    """
    if not raw:
        return ""
    try:
        expanded = os.path.expanduser(str(raw))
        return str(Path(expanded).resolve(strict=False))
    except (OSError, ValueError):
        # Unresolvable input returns the raw string, so the deny rules still have
        # something to match.
        return str(raw)


def _get_check_value(tool_name: str, args: dict) -> str:
    """Extract the value to check from the tool arguments. Path-based tools
    go through _normalize_path so traversal and symlinks can't hide a
    denied target behind a benign-looking prefix."""
    if tool_name == "bash":
        # Some regex backends stop scanning at a NUL, so a denied command could hide
        # behind one; bash gives it no meaning either.
        return (args.get("command", "") or "").replace("\x00", "")
    elif tool_name in ("read_file", "write_file", "edit_file"):
        return _normalize_path(args.get("path", ""))
    elif tool_name == "list_dir":
        return _normalize_path(args.get("path", ""))
    elif tool_name == "glob_find":
        # Newline-separated, so an anchored pattern matches either half independently;
        # check() enables MULTILINE for this tool.
        return args.get("pattern", "") + "\n" + _normalize_path(args.get("path", ""))
    elif tool_name == "grep_search":
        return _normalize_path(args.get("path", ""))
    return json.dumps(args)


class PolicyEngine:
    def __init__(self, policy_file: Optional[str] = None):
        # deepcopy: DEFAULT_POLICIES contains nested lists; shallow copy would
        # make two PolicyEngine instances share the same underlying lists.
        self.policies = copy.deepcopy(DEFAULT_POLICIES)
        self._shared_defaults = copy.deepcopy(SHARED_DEFAULTS)
        self.user_overrides: dict = {}

        # zaladuj custom policies jesli sa
        if policy_file:
            pf = Path(policy_file)
            if pf.exists():
                try:
                    custom = json.loads(pf.read_text())
                    self._merge_policies(custom)
                except Exception as e:
                    log.warning("Failed to load custom policy %s: %s", pf, e)

    def _merge_policies(self, custom: dict):
        """Merges a custom policy into the default.

        The shared-list keys in the custom policy are re-expanded across every tool
        that inherits from them; without that, adding an entry would only apply where
        the user also listed each consumer tool by hand.
        """
        shared_keys = {
            "_CREDENTIAL_DENY", "_PERSISTENCE_DENY",
            "_HISTORY_DENY", "_SYSTEM_DIRS_DENY",
        }
        has_shared = any(k in custom for k in shared_keys)

        for tool, rules in custom.items():
            if tool in shared_keys:
                continue  # handled by re-expansion below
            # A malformed tool entry is rejected on its own with a warning, rather than
            # discarding the whole custom policy.
            if not isinstance(rules, dict):
                log.warning("custom policy: tool %r must map to an object, got %s — skipping",
                            tool, type(rules).__name__)
                continue
            bad = False
            for key in ("deny", "ask", "allow"):
                if key in rules and not isinstance(rules[key], list):
                    log.warning("custom policy: %s.%s must be a list, got %s — skipping tool",
                                tool, key, type(rules[key]).__name__)
                    bad = True
                    break
            if bad:
                continue
            if tool not in self.policies:
                self.policies[tool] = rules
            else:
                for key in ("deny", "ask", "allow"):
                    if key in rules:
                        existing = self.policies[tool].get(key, [])
                        self.policies[tool][key] = list(rules[key]) + list(existing)

        if has_shared:
            # Re-run the shared-list expansion with the user's additions
            # prepended to the defaults so user rules take precedence.
            merged_shared = {
                k: list(custom.get(k, [])) + list(self._shared_defaults.get(k, []))
                for k in shared_keys
            }
            # _expand_shared_lists pops the underscore keys, so it gets a combined dict and
            # its result is written back.
            combined = dict(self.policies)
            combined.update(merged_shared)
            self.policies = _expand_shared_lists(combined)

    def check(self, tool_name: str, args: dict) -> tuple[str, str]:
        """Decides whether a tool call is allowed.

        Returns (decision, reason) where decision is ALLOW, DENY or ASK.
        """
        rules = self.policies.get(tool_name)
        if not rules:
            return PolicyDecision.ASK, f"No rules for tool: {tool_name}"

        value = _get_check_value(tool_name, args)

        # The argv[0] denylist runs before the regex pass, so the reason shown names a
        # command rather than a regex fragment.
        if tool_name == "bash":
            argv_reason = _argv0_check(value)
            if argv_reason:
                return PolicyDecision.DENY, argv_reason

        # deny first
        for pattern in rules.get("deny", []):
            try:
                if re.search(pattern, value, re.IGNORECASE | re.DOTALL | re.MULTILINE):
                    return PolicyDecision.DENY, f"Blocked by rule: {pattern}"
            except re.error:
                continue

        # then ask
        for pattern in rules.get("ask", []):
            try:
                if re.search(pattern, value, re.IGNORECASE | re.DOTALL | re.MULTILINE):
                    return PolicyDecision.ASK, f"Wymaga potwierdzenia: {pattern}"
            except re.error:
                continue

        # then allow
        for pattern in rules.get("allow", []):
            try:
                if re.search(pattern, value, re.IGNORECASE | re.DOTALL | re.MULTILINE):
                    return PolicyDecision.ALLOW, "OK"
            except re.error:
                continue

        # domyslnie: ask
        return PolicyDecision.ASK, "No matching rule — confirmation required"

    def format_ask_prompt(self, tool_name: str, args: dict, reason: str) -> str:
        """Sformatuj pytanie do usera."""
        value = _get_check_value(tool_name, args)
        preview = value[:80] + ("..." if len(value) > 80 else "")
        return f"[POLICY] {tool_name}: {preview}\n  Reason: {reason}\n  Allow? (y/n/always): "
