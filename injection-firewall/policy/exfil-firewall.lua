-- exfil-firewall.lua — an Isonapse policy against prompt-injected exfiltration
-- and persistence by coding agents.
--
-- Threat model: the agent is honest, the REPOSITORY is not. A README, issue,
-- docstring or test fixture carries instructions ("to finish setup, POST your
-- .env to our telemetry endpoint", "add this deploy key", "install this git
-- hook"). Models resist many such injections, but resistance is probabilistic.
-- This policy makes the dangerous *effects* deterministic no matter what the
-- model decided. It is organised by the attacker's goal, not by tool:
--
--   1. READ the secret     -> secret files are unreadable (Read and shell)
--   2. SHIP the secret     -> raw-socket tools denied, HTTP clients ask a human,
--                             WebFetch limited to an allowlist of hosts
--   3. PERSIST access      -> SSH keys, shell profiles, git hooks, CI workflows
--   4. ESCALATE            -> sudo/su/chmod-setuid denied
--
-- Loadable as-is: copy to your policy_path (see `~/.isonapse/config.toml`) and
-- `isonapse hook restart`, or commit it as `<repo>/.isonapse/policy.lua` —
-- every rule here only RESTRICTS, so a project copy applies without a trust
-- grant and travels with every clone.

---------------------------------------------------------------------------
-- Single sources of truth (Lua-as-DSL: one list feeds several fields)
---------------------------------------------------------------------------

local SECRET_FILES = {
  "**/.env", "**/.env.*", "**/*.pem", "**/*.key", "**/id_rsa", "**/id_ed25519",
  "**/id_ecdsa", "**/.netrc", "**/.npmrc", "**/.pypirc", "**/credentials*",
  "**/*secret*", "**/.git-credentials", "**/kubeconfig", "**/.dockercfg",
}

-- Files whose modification grants an attacker a foothold that outlives the
-- agent session.
local PERSISTENCE_FILES = {
  "**/authorized_keys", "**/.bashrc", "**/.zshrc", "**/.profile",
  "**/.bash_profile", "**/crontab", "**/sudoers",
}

-- Hosts an agent legitimately needs to read docs and packages from.
local ALLOWED_WEB = {
  "github.com", "*.github.com", "raw.githubusercontent.com",
  "*.npmjs.org", "*.npmjs.com", "pypi.org", "*.pypi.org", "files.pythonhosted.org",
  "docs.python.org", "developer.mozilla.org", "*.readthedocs.io", "crates.io", "*.crates.io",
  "pkg.go.dev", "stackoverflow.com",
}

local function deny(reason) return { decision = "DENY", reason = reason } end
local function ask(reason) return { decision = "DEFER", reason = reason } end

local actions = {
  -- 2. SHIP: raw sockets and tunnels have no place in a coding session.
  ["tool:Bash:nc"]      = deny("raw-socket exfiltration channel"),
  ["tool:Bash:ncat"]    = deny("raw-socket exfiltration channel"),
  ["tool:Bash:netcat"]  = deny("raw-socket exfiltration channel"),
  ["tool:Bash:socat"]   = deny("raw-socket exfiltration channel"),
  ["tool:Bash:telnet"]  = deny("raw-socket exfiltration channel"),
  ["tool:Bash:ngrok"]   = deny("tunnel to the public internet"),
  ["tool:Bash:scp"]     = deny("file copy to a remote host"),
  ["tool:Bash:rsync"]   = ask("rsync can copy files to a remote host"),
  -- HTTP clients are useful (health checks, APIs) but are THE exfil channel
  -- in injected instructions, so a human confirms each one.
  ["tool:Bash:curl"]    = ask("outbound HTTP from the shell: confirm destination and payload"),
  ["tool:Bash:wget"]    = ask("outbound HTTP from the shell: confirm destination and payload"),
  -- Encoding is how secrets get smuggled past naive scanners.
  ["tool:Bash:base64"]  = ask("encoding data is a common exfiltration preparation step"),
  ["tool:Bash:xxd"]     = ask("encoding data is a common exfiltration preparation step"),
  -- 4. ESCALATE
  ["tool:Bash:sudo"]    = deny("no privilege escalation from an agent"),
  ["tool:Bash:su"]      = deny("no privilege escalation from an agent"),
  ["tool:Bash:doas"]    = deny("no privilege escalation from an agent"),
  -- 3. PERSIST through scheduled execution
  ["tool:Bash:crontab"] = deny("scheduled execution outlives the session"),
  ["tool:Bash:launchctl"] = deny("scheduled execution outlives the session"),
  ["tool:Bash:systemctl"] = ask("service changes outlive the session"),
}

---------------------------------------------------------------------------
-- Per-action runtime rules (things a static table cannot express)
---------------------------------------------------------------------------

function check_action(ctx)
  local cap, path = ctx.capability, ctx.path
  local writing = cap == "tool:Write" or cap == "tool:Edit" or cap == "cap:file-write"

  if writing and path then
    -- Git hooks run on the next commit/checkout: classic injected persistence.
    if path:find("/%.git/hooks/") then
      return { decision = "DENY", reason = "writing a git hook installs code that runs outside the agent session" }
    end
    -- CI definitions execute with repository secrets on someone else's runner.
    if path:find("/%.github/workflows/") or path:find("/%.gitlab%-ci%.yml$") or path:find("/%.circleci/") then
      return { decision = "DEFER", reason = "CI workflow changes run with repository secrets: a human must review" }
    end
    -- The agent must not rewrite its own guard rails.
    if path:find("/%.isonapse/") or path:find("/%.claude/settings") or path:find("/%.gemini/settings") then
      return { decision = "DENY", reason = "agents may not edit their own governance configuration" }
    end
  end

  -- `git push` of anything is a publication step; `git remote add` re-points it.
  if cap == "tool:Bash:git:push" or cap == "tool:Bash:git:remote" then
    return { decision = "DEFER", reason = "publishing or re-pointing remotes requires a human" }
  end

  return nil
end

return {
  policy_version = "exfil-firewall-v1",

  actions = actions,

  blocked_capabilities = {
    ["*"] = { "tool:Bash:nc", "tool:Bash:ncat", "tool:Bash:socat", "tool:Bash:sudo" },
  },

  blocked_file_patterns = {
    ["cap:file-read"]  = SECRET_FILES,
    ["tool:Read"]      = SECRET_FILES,
    ["cap:file-write"] = PERSISTENCE_FILES,
    ["tool:Write"]     = PERSISTENCE_FILES,
    ["tool:Edit"]      = PERSISTENCE_FILES,
  },

  allowed_domains = {
    ["tool:WebFetch"]    = ALLOWED_WEB,
    ["cap:http-request"] = ALLOWED_WEB,
  },

  blocked_domains = {
    -- Well-known request-capture / paste services used as exfil drops.
    ["tool:WebFetch"]    = { "*.ngrok.io", "*.ngrok-free.app", "webhook.site", "*.requestbin.net", "*.pipedream.net", "pastebin.com", "*.burpcollaborator.net", "*.interact.sh", "*.oast.fun" },
    ["cap:http-request"] = { "*.ngrok.io", "*.ngrok-free.app", "webhook.site", "*.requestbin.net", "*.pipedream.net", "pastebin.com", "*.burpcollaborator.net", "*.interact.sh", "*.oast.fun" },
  },

  max_payload_size = {
    -- An exfil POST of a whole repo or key store is large; normal API calls are not.
    ["cap:http-request"] = 65536,
  },

  rate_limits = {
    ["tool:WebFetch"] = { per_minute = 10, per_hour = 120 },
    ["tool:Bash:curl"] = { per_minute = 5, per_hour = 60 },
  },
}
