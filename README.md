# bw-touch

Touch ID for the [Bitwarden CLI](https://bitwarden.com/help/cli/) on macOS, with an agent skill that lets Claude Code, Codex and similar tools use vault secrets without seeing your master password.

`bw-touch` takes the same arguments as `bw`. When the vault is locked it asks for your fingerprint, unlocks with a master password kept in your login keychain, and runs the command. It never prints or exports a session key.

```console
$ bw-touch list items --search github
$ bw-touch get password 0f8fad5b-d9cb-469f-a165-70867728950e
```

bw-touch is an independent project and is not affiliated with Bitwarden.

## Requirements

- macOS 13 or later on a Mac with Touch ID
- The Bitwarden CLI, `bw`, on your `PATH` (`brew install bitwarden-cli`)
- Swift 5.9 or later to build (Xcode or the Command Line Tools)

## Install

```bash
git clone https://github.com/metrovoc/bw-touch.git
cd bw-touch
make install
```

This builds a release binary, installs it to `~/.local/bin/bw-touch` and signs it. Set `PREFIX` to install elsewhere.

Then store your master password, entering your Bitwarden account email:

```bash
bw-touch setup you@example.com
```

`setup` reads the master password from the terminal without echoing it and saves it to your login keychain, readable only by the `bw-touch` binary.

If your account uses two-step login, log in once with `bw login` first. bw-touch then only has to unlock the vault.

## How authorization works

- The first command against a locked vault shows a Touch ID prompt. A prompt left unanswered gives up after 60 seconds.
- An approval opens the vault until 15 minutes pass without a command. bw-touch then locks it again.
- An item read by its exact ID during that window (`get item`, `get password`, `get totp` and the other `get <field> <id>` forms) stays readable by that ID for 24 hours without another prompt. Searches and other items need a new approval.
- `bw-touch lock` locks the vault at once and ends every 24-hour lease.

`create item` and `edit item <id>` accept the encoded JSON on standard input, as `bw` does.

## Security model

- The master password is a generic password item in your login keychain whose access list holds only the `bw-touch` binary, identified by its code signature. macOS asks for your login password before letting any other program read it.
- The Touch ID check is made by bw-touch itself before it reads that item.
- A background agent, started on demand, holds the authorization state and listens on a Unix socket in `~/Library/Caches/bw-touch` that only your user can open. Any process running as you can send it commands, so while the 15-minute window is open, every such process has the vault access you approved, and leased items stay available to them for 24 hours.
- bw-touch passes the master password to `bw` on standard input for the commands that need it. Whatever `bw` it finds on `PATH` receives that password, so keep the directory holding `bw` writable only by you.

### Upgrading

`make install` signs ad hoc by default, which ties the keychain item to that exact build. After you install a new build, macOS asks for your login password the first time it reads the credential; choose Always Allow. Signing every build with the same certificate avoids this:

```bash
make install SIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)" SIGN_IDENTIFIER=com.example.bw-touch
```

To remove the stored credential, for example before running `setup` for another account:

```bash
security delete-generic-password -s bitwarden.cli-master-password
```

## Agent skill

`skills/bitwarden-vault` teaches a coding agent to use the vault through bw-touch. Its helper, `bw_vault.py`, is read-only. It searches with metadata only, lists an item's fields without their values, and delivers a secret either to you on request or straight into one child process as an environment variable or standard input, so the value stays out of the agent's transcript.

Install bw-touch first, then add the skill in one of these ways.

As a Claude Code plugin:

```
/plugin marketplace add metrovoc/bw-touch
/plugin install bw-touch@bw-touch
```

As a linked skill, from the cloned repository:

```bash
ln -s "$PWD/skills/bitwarden-vault" ~/.claude/skills/bitwarden-vault   # Claude Code
ln -s "$PWD/skills/bitwarden-vault" ~/.agents/skills/bitwarden-vault   # Codex
```

The helper also works on its own:

```bash
python3 skills/bitwarden-vault/scripts/bw_vault.py search "GitHub"
python3 skills/bitwarden-vault/scripts/bw_vault.py inspect ITEM_ID
python3 skills/bitwarden-vault/scripts/bw_vault.py run --env GH_TOKEN ITEM_ID login.password -- gh auth status
```

## Development

```bash
make test
```

## License

[MIT](LICENSE)
