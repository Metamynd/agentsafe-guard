# Contributing

## How this repository works, stated plainly

These packages are developed inside MetaMynd's main repository, which is private, and published
here on each release. The history is real — every commit you see is the commit that was made —
but this is not where the branch you would base a PR on actually lives.

**That means a pull request here takes a manual step on our side.** We read it, port the change
into the main repository with your authorship preserved, and it lands here on the next publish.
It works, and it is slower than a normal PR. We would rather tell you that up front than let
you discover it after a week of silence.

If external contribution ever gets busy enough that this is the bottleneck, we will move the
evaluator to being the source of truth here and depend on it from the other side. It is not
busy enough yet.

## What is most useful

- **A failing test.** The evaluator is a pure function; if you can express the bug as a case in
  `packages/policy-core/*.test.ts`, we can fix it fast and it stays fixed.
- **Verdict disagreements.** If you implement the protocol in another language and reach a
  different verdict for the same inputs than this evaluator does, that is either our bug or a
  gap in the [spec](https://metamynd.ai/developers/spec). Both are worth a report.
- **Another language client.** The canonical signing format is published and there is a
  [Python reference](https://metamynd.ai/developers/python). If you build one, tell us.
- **Documentation that was wrong or missing when you needed it.**

Security issues do **not** go here — see [SECURITY.md](SECURITY.md).

## Running it

```bash
npm install     # vitest, for the evaluator's TypeScript suite
npm test        # evaluator suite + both guards' smoke suites
```

No network, no account, no database. If `npm test` needs any of those, that is a bug in the
test, not in your setup.

## House style

The code here is heavier on comments than most, and deliberately so: they explain **why** a
thing is the way it is, especially where the obvious approach was tried and was wrong. Several
of them describe a specific bug and the reasoning that fixed it. If you change behaviour that
one of those comments justifies, please update the comment in the same commit — a stale
explanation is worse than none, because it is believed.

Match the surrounding code for everything else. There is no separate style guide and there is
no linter to argue with.

## A note on the generated evaluator

`packages/*/policy-core.mjs` is **generated** from `packages/policy-core/` by esbuild — the
banner at the top of each says so. Edit the TypeScript, never the bundle. A patch against the
bundle cannot be merged, because the next release would overwrite it.

## Licence

By contributing you agree that your contribution is licensed under the
[MIT License](LICENSE), the same terms as the rest of this repository.
