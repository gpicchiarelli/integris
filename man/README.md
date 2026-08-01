# Manual pages

Sources are [mdoc](https://man.openbsd.org/mdoc.7) and install on every
declared Integris target (macOS, FreeBSD, Linux, OpenBSD).

| Page | Section | Installs with |
|------|---------|---------------|
| `integris-assure.1` | 1 | engineering CLI |
| `integris-evidence.1` | 1 | engineering CLI |
| `integris-release-digest.1` | 1 | engineering CLI |
| `integris-verify-config.1` | 1 | engineering CLI |
| `integris-role-stub.1` | 1 | Unix engineering helper |
| `integris-crash-stub.1` | 1 | Unix engineering helper |
| `integris.7` | 7 | overview |
| `integrisd.8` | 8 | reserved daemon page (binary not yet shipped) |

## Layout

Default (FHS, Homebrew, many Linux/FreeBSD packages):

```sh
make PREFIX=/usr/local install-man
# → ${PREFIX}/share/man/man{1,7,8}/
```

Traditional BSD ports layout (common on OpenBSD; also valid on FreeBSD):

```sh
make PREFIX=/usr/local MANDIR=/usr/local/man install-man
```

Staged packaging:

```sh
make DESTDIR=/tmp/stage PREFIX=/usr install-man
```

## Lint

```sh
make man-lint
```

Requires `mandoc`. Pages are shipped uncompressed; packagers may gzip at
package build time.
