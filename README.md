vw-cli
===

A pure-go implementation of a [Bitwarden][bitwarden] CLI client.

TOC
===
- [Design Choices](#design-choices)
- [Usage](#usage)
  1. [Login](#login)
  2. [Unlock [optional]](#unlock-optional)
  3. [List](#list)
  4. [Show](#show)

Design Choices
===

1. Zero dependencies: This repository must be self-sufficient and your only
   dependency must be the go compiler. If there's no other way around, then
   vendor the dependency in-tree.

   See the naïve implementation of `askPass` and a [Cobra][go-cobra]-like
   `Command` struct.

2. Read-only: This tool does not create new
   ciphers/secrets/organizations/collections in your Bitwarden vault.

3. Only one account is supported: if desired, then use the `--config-dir` flag
   to manage multiple accounts.

4. Security in mind but not a priority: There's absolutely no real
   in-depth _security_ practices (the likes of keeping the decrypted data in
   memory as little as possible, zeroing unused memory, so on and so forth), but
   the data we keep at rest (the sync endpoint's response) is kept encrypted at
   rest.

5. `text` Output format is meant to be to ease in usages of the CLI in
   automation, but in no way is expected to be structured (like: yaml, json,
   etc.)


Usage
===

Compile it yourself, someday I'll figure the whole release thing.

```bash
git clone https://github.com/josegomezr/vw-cli.git vw-cli
cd $_
make
# move ./vw-cli to your preferred $PATH location.
```

## Login

Authenticates & pulls the password store to your machine. The password store
remains encrypted and will only be decrypted when reading it, never decrypted at
rest.

```bash
$ vw-cli login --api-client-id user.<uuid from bitwarden>
# or
$ vw-cli login --email <your bitwarden email>
```

## Unlock [optional]

Unlock creates a temporary key that's used to encrypt your master key, the
resulting session key allows you to read your store without having to input
your master password every time.

Watch out: this feature is still under review, I reverse engineered what I could
understand out of the [Bitwarden NodeJS Client][bitwarden-clients].

```bash
$ vw-cli unlock
Master password: 

Make sure to export the following variable:
export VW_SESSION="<random base64 things here>"
Or pass --session-token "<random base64 things here>" to the next $ vw-cli invocations
```

The plain text output is perfect for automating this step like:

```bash
export VW_SESSION=$(vw-cli unlock --output-format plain)
```

## List

Lists all items in the vault

```bash
$ vw-cli list
---
Id: 00000000-0000-4000-0000-000000000000
Name: Item name
Organization: Organization Name when present (00000000-0000-4000-0000-100000000000)
Folder: Folder name when present (00000000-0000-4000-0000-200000000000)
...
# [rinse and repeat]
```

## Show

Shows the details of a specific item in the vault.

```bash
$ vw-cli show [--folder "folder-name or uuid"] [--organization "org-name or uuid"] "Item Name or uuid" [attribute]
Id: 00000000-0000-4000-0000-000000000000
Name: <Item Name>
Login-Username: <Login-Username if defined else not printed>
Login-Uri: <Login-Uri if defined else not printed>
Notes: <Notes if defined else not printed>
Login-Totp: [PROTECTED]
Login-Password: [PROTECTED]
```

By default the show command will not show any password/TOTP secret. To show
password and/or TOTP you must explicitly pass: `--with-password` or
`--with-totp`.

When any of those flags, the respective `[PROTECTED]` field will be revealed.

If a specific attribute is wanted, you can query it directly as:
```bash
$ vw-cli show 00000000-0000-4000-0000-000000000000 login.password
da real password
$ vw-cli show 00000000-0000-4000-0000-000000000000 login.totp
000000
```

Supported attributes:

- `name`
- `notes`
- `login.password`
- `login.username`
- `login.totp`
- `login.totp`
- `login.totp-source`

Note that when asking for the attribute explicitly, there's no need to pass
`--with-password`/`--with-totp` as the presence of the attribute is an explicit
enough request.

[go-cobra]: https://github.com/spf13/cobra
[bitwarden]: https://bitwarden.com/
[bitwarden-clients]: https://github.com/bitwarden/clients
