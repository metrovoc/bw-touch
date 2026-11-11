---
name: bitwarden-vault
description: Retrieve or securely inject credentials and private information from the user's Bitwarden vault through the local bw-touch Touch ID bridge on macOS. Use when a task needs an API key, token, password, username, secure note, card or identity detail, custom field, or TOTP stored in Bitwarden, or when the user asks to search or read the vault. The bundled helper is read-only.
---

# Bitwarden Vault

Use `scripts/bw_vault.py` from this skill directory. It keeps complete item JSON and retrieved values inside the helper unless the user explicitly asks to see a value.

The helper needs [`bw-touch`](https://github.com/metrovoc/bw-touch) on `PATH` or in `~/.local/bin`, already set up with `bw-touch setup <email>`. If it is missing or reports no stored credential, point the user to the repository's install steps; setup asks for the master password in their own terminal, so do not run it for them.

## Retrieve an item

1. Search narrowly with a user-supplied name, service, account, or URL:

   ```bash
   python3 scripts/bw_vault.py search "OpenAI"
   python3 scripts/bw_vault.py search --url "https://api.openai.com"
   ```

   Search output contains candidate IDs and only enough metadata to distinguish them. Pass URLs without embedded credentials, query strings, or fragments. Never list the whole vault or print raw `bw list items` output.

2. Select an exact item ID. Prefer an exact name plus matching username or URI host. If several candidates remain and the user's intent does not resolve them, show the candidate metadata and ask; never guess a credential.

3. Inspect available fields without values only when the desired selector is unclear:

   ```bash
   python3 scripts/bw_vault.py inspect ITEM_ID
   ```

   Common selectors are `notes`, `login.username`, `login.password`, `login.uris[0].uri`, `field:Exact custom field name`, and `totp` for the current one-time code. Any other selector printed by `inspect` with `set: true` is also valid.

4. Choose delivery based on intent:

   - If the user explicitly asked to see or copy the value, reveal only that field:

     ```bash
     python3 scripts/bw_vault.py read ITEM_ID SELECTOR --reveal
     ```

   - If a program needs a secret, inject it into only that child process. Do not reveal it first:

     ```bash
     python3 scripts/bw_vault.py run --env API_TOKEN ITEM_ID SELECTOR -- command arg
     python3 scripts/bw_vault.py run --stdin ITEM_ID SELECTOR -- command arg
     ```

   `run` executes the command directly without a shell. Use an environment variable name the target program natively supports, or its password-from-stdin mode.

## Freshness and authorization

- Use the local `bw-touch` bridge, never raw `bw`, a master-password prompt, or `BW_SESSION`. Touch ID is the authorization boundary; do not ask the user to paste the master password.
- Every search syncs the local vault first and stops if sync fails, so stale cached metadata is not returned. For direct item access without a fresh search, run `python3 scripts/bw_vault.py sync` first.
- A sandbox may block the GUI authorization agent or Bitwarden's local data lock. Retry the same helper command outside the sandbox before diagnosing `bw-touch` or the vault.
- Stop after a declined, cancelled, or timed-out Touch ID prompt; an unanswered prompt gives up after 60 seconds. Do not loop authorization attempts.
- A Touch ID approval opens the whole vault for 15 idle minutes. An item read by exact ID during that window (`inspect`, `read`, or `run`) stays readable by that ID for 24 hours without another prompt; searches and other items need a new approval.
- For long or unattended work, resolve every item the task needs while the user is present, keep the exact IDs, and later use `sync` plus `read` or `run` instead of searching again.
- Use `python3 scripts/bw_vault.py lock` only when the user requests immediate locking; it also ends every 24-hour lease.

## Secret boundaries

- Scope every search and read to the active user request. Do not explore unrelated vault entries.
- Treat passwords, API keys, tokens, TOTP data, hidden fields, card details, private keys, and secure-note contents as secrets. Reveal one only when explicitly requested; otherwise report that it was retrieved or used without echoing it.
- Keep secrets out of command text, argv, files, shell history, global environment variables, logs, verbose HTTP traces, and assistant commentary. Do not use shell expansion, `sh -c`, `env`, `printenv`, or tracing around an injected command.
- The helper does not create, edit, delete, export, or attach vault data. A request to mutate Bitwarden must be explicit and handled separately with an exact target; it is not implied by retrieval access.
