# Persistent data and migration

Compose uses `./.data:/data`. This bind mount hides any `/data` already inside an
older container; it does not copy that data to the host. **Do not run
`docker compose down`, delete the old container, or recreate it before verifying
a complete backup.** The settings JSON export contains software authenticators,
not the complete Chromium profile, website sessions or management configuration.

## First deployment

`docker compose up --build -d` creates the dedicated `./.data` directory. The
entrypoint initializes only an empty directory to container UID/GID 10001 and
mode 0700, then runs the services as a non-root user. An ordinary host user may
not be able to read it directly; this protects stored private keys. Do not use a
symlink, the project root, or a general-purpose directory as the data source.

## Existing deployment

Changing the host path from `./data` to `./.data` does not migrate files. Keep the
existing source and old container intact until a separate full backup is verified.
Never run two instances against the same Chromium profile.

First use `docker ps -a` and inspect the exact container's mounts to establish
whether the real data is already in a host bind directory or only inside the
container. If the old service is available, export a software-key backup from
Settings as an additional precaution. Stop the verified container with
`docker stop OLD_CONTAINER_ID` and keep it stopped while copying or moving data.

### A. Existing project-local host bind at `./data`

Use this route only after verifying that the old container actually binds this
specific directory. Save and verify a complete offline backup of that stopped
source, including the profile and management file. Then, from the verified project
directory, this guarded command renames the existing host directory without
copying or changing its contents or ownership:

```sh
test -d ./data && test ! -L ./data &&
  test ! -e ./.data && test ! -L ./.data &&
  mv ./data ./.data
```

The source must be a real directory, not a symlink. Both destination checks are
required: `test ! -e` alone also succeeds for a dangling symlink. If any check fails,
stop and inspect; do not overwrite, merge or remove either path. This is an
instruction for the deployment owner, not a migration performed by the application.
Afterward, **do not restart the old configuration that still points to `./data`**;
it could create an empty directory and start against the wrong data. Apply the
updated `./.data:/data` configuration only after the checks below.

### B. Data held inside the old container or another verified source

For container-local data, copy from the retained stopped container. Substitute its
verified ID; `./.data` must not exist, including as a dangling symlink. If it already
exists, inspect its origin and contents instead of overwriting it. `-a` preserves
source UID/GID; do not add `-L`, which follows symlinks.

```sh
test ! -e ./.data && test ! -L ./.data &&
  docker cp -a OLD_CONTAINER_ID:/data ./.data
```

Keep a separate full backup after confirming that the copy is complete. An old
bind at a different host path needs the same stopped-source and verified-copy
precautions; do not assume the project-local rename command applies to it.

### Verify before recreation

1. Confirm the destination contains the complete original files and that an
   independent full backup exists. With native Linux Docker, `/data` must belong
   to UID 10001 with mode 0700; existing files retain their source ownership.
   If preserving ownership fails, an administrator may need to help with this
   verified dedicated copy. Do not recursively chown arbitrary host directories.
   Docker Desktop/rootless mappings can differ; inspect actual mount permissions.
2. Only then run `docker compose up --build -d --no-deps webauthn-browser`. This
   can recreate a same-named service container. An old `auth-browser` service may
   remain; keep it stopped to avoid shared ports or concurrent profile access.
3. Check the original keys, access passwords and browser profile after startup.
   Retain the backup and old stopped container until those checks pass.

The entrypoint refuses to recursively repair a nonempty directory with
incompatible ownership. It rejects symlinks for managed top-level files and
directories and never uses `chmod 777`. Repeated startup does not reset stored
keys, passwords or profiles. Permission errors fail visibly rather than silently
creating another data set. This documentation does not rename the host directory.

References: [docker cp](https://docs.docker.com/reference/cli/docker/container/cp/)
and [bind mounts hide existing contents](https://docs.docker.com/engine/storage/bind-mounts/#bind-mounting-over-existing-data).

## Software-authenticator compatibility

The service continues reading the same `auth-browser.json` and Chromium profile.
Existing ES256 PKCS#8 private keys, credential IDs, RPs, user handles and signature
counters from the earlier CDP format remain compatible. Unsupported algorithms
fail explicitly without discarding the stored data. Legacy automatic-presence
and simulated-UV fields remain readable for compatibility but grant no approval.

When a request first needs UV for an existing key, the outer page asks you to set
that key's local password. It is separate from the VNC and Settings passwords and
is not a hardware PIN. Existing website credentials are not re-registered by this
step. Exported backups contain private keys and key-password hashes; keep them
private. A full offline data-directory backup remains recommended before upgrading.
