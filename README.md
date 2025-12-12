vw-cli
===

A pure-go implementation of a bitwarden CLI client.


CLI Interface
---
```bash
vw-cli help
vw-cli [--session-token ...] [--config-dir "/custom/config-dir"] login [--api-client-id "key"] [--api-client-secret "secret"]
vw-cli [--session-token ...] [--config-dir "/custom/config-dir"] unlock [--check] [-master-password-file]
vw-cli [--session-token ...] [--config-dir "/custom/config-dir"] list [--folder "folder id or name"] [--organization "organization id or name"]
vw-cli [--session-token ...] [--config-dir "/custom/config-dir"] show [--folder "folder id or name"] [--organization "organization id or name"] secret-name-or-id
```

Usage
---

### 1. Login

Authenticates & pulls the password store to your machine. The password store
remains encrypted and will only be derypted when reading it, never decrypted at
rest.

As of now only with api credentials. Email/PW will come someday in the future.

```bash
vw-cli login --api-client-id user.<uuid from bitwarden>
```


### 2. Unlock [optional]

Unlock creates a temporary key that's used to encrypt your master key, the
resulting session key allows you to read your store without having to input
your master password every time.

Watch out: this feature is still under review, I reverse engineered what I could
understand out of the NodeJS Client.

```bash
vw-cli unlock --api-client-id user.<uuid from bitwarden>

Master password: 
Make sure to export the following variable:
export VW_SESSION="<random base64 things here>"
Or pass --session-token "<random base64 things here>" to the next vw-cli invocations
```

### 3. List

Lists all items in the store

```bash
./vw-cli list

uuid|path|organization
00000000-0000-4000-0000-000000000000| folder and name | <organization or empty>
00000000-0000-4000-0000-000000000000| folder/name | 
00000000-0000-4000-0000-000000000000| folder/name | organization name
```

### 4. Show

Shows the details of a specific item in the vault.

Note: The password/TOTP **will never** be printed by default.

```bash
./vw-cli show 00000000-0000-4000-0000-000000000000
Id: 00000000-0000-4000-0000-000000000000
Name: <Item Name>
Login-Username: <Login-Username if defined else not printed>
Login-Uri: <Login-Uri if defined else not printed>
Notes: <Notes if defined else not printed>
```

To show password and/or TOTP you must explicitly pass: `--with-password` or
`--with-totp`. Then:

```
Login-Totp: <Login-Totp if defined else not printed>
Login-Password: <Login-Password if defined else not printed>
```

Will appear in the output respectively.

If a specific attribute is wanted, you can query it directly as:

```bash
./vw-cli show 00000000-0000-4000-0000-000000000000 login.password
da real password
./vw-cli show 00000000-0000-4000-0000-000000000000 login.totp
000000
```

Supported attributes:

- `name`
- `notes`
- `login.password`
- `login.username`
- `login.totp`
