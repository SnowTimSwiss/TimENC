# Writing release notes

Every release gets a notes file in [`docs/releases/`](releases/), named after
its Git tag (`v3.2.0.md`). Copy the template below, fill it in, delete what
doesn't apply, and publish it with `docs/releases/apply.sh`.

## Names

* Every **minor** version (the 0.1 steps: 3.0, 3.1, 3.2, ...) gets a short
  codename. Patch releases (3.2.1) keep the name of their minor version and don't
  get their own.
* Names start at 1.0. The alphas are just "Alpha 1.1", "Alpha 2.0" and so on.
* One or two words, easy to remember, ideally with a wink at what the release
  is about ("Deadbolt" for the security release, "Smöl" for compression).
* Don't reuse a name.

| Version | Name |
|---------|------|
| 1.0 | Day One |
| 1.1 | Polish |
| 1.2 | Streamline |
| 1.3 | Terminal |
| 2.0 | Speeeed |
| 2.1 | Safe Heaven |
| 2.2 | Smöl |
| 3.0 | Deadbolt |
| 3.1 | Belt and Braces |
| 3.2 | Overdrive |
| 4.0 | Featherweight |

## Title

* Minor or major: `v3.0.0 - Deadbolt`
* Patch: `v3.0.1`

The first line of a notes file is the title, the second is empty, and the rest
is the release body.

## Tone

* Write like you'd explain it to a friend who uses the app, not like a press
  release. Short sentences, concrete things.
* Say what changed for the user first, how it works second.
* No emoji headings, no "blazing fast", no "robust". If something got faster,
  say how much and on what.
* Be honest about bugs and limits. A fixed security problem gets a clear
  sentence about what it was, not a vague "hardening".
* Mention a format change and whether old files and old versions still work.

## Template

````markdown
v<X.Y.Z> - <Name>

<One or two sentences: what is this release about?>

> [!WARNING]
> <Only if something breaks: files other versions can't open, removed
> features, changed behaviour. Delete this block otherwise.>

### What's new
* <thing, from the user's point of view>

### Fixed
* <bug, and what it did to you>

### Security
* <only if relevant: what the problem was, who could exploit it, how it is fixed>

### Compatibility
| | |
|---|---|
| Reads | <file formats this version can open> |
| Writes | <file format it creates> |
| Older TimENC versions | <can / cannot open the files from this version> |

**Full changelog:** https://github.com/SnowTimSwiss/TimENC/compare/<previous-tag>...<this-tag>
````

Leave out sections that are empty. A patch release is often only a summary line
and a "Fixed" list.

## Publishing

```bash
docs/releases/apply.sh            # update every release from its file
docs/releases/apply.sh v3.2.0     # just one
```

The script needs the GitHub CLI (`gh`), logged in with write access to the
repository, and runs `gh release edit` for each tag.
