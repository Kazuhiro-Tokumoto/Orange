# If you find a vulnerability

[English](SECURITY.md) · [日本語](SECURITY.jp.md)

Send it to `manh@manh2309.org`.

**Please do not open a public Issue.** Anything that lets someone steal funds or
break the chain gets read before it gets fixed. Everything else — crashes,
stalled sync, a display that looks wrong — is fine as an Issue. When in doubt,
email.

English or Japanese, either is fine.

## Said up front

**This is one person's hobby project.** There is no company and no team.

- **No commitment to respond.** There may not be time to look, replies may be
  slow, and some reports may go unanswered
- **No bounty.** There is no money to pay one from
- **No deadlines.** If you tell me "I will publish in 90 days", there is no
  guarantee I can work to that

If you find something you need fixed quickly, **fork it and fix it.** It is MIT,
so you need nobody's permission. That is the more reliable route.

If staying quiet does not suit you, publish it. No hard feelings.

That said, I have plenty of free time, so I do generally reply.

## What is most worth sending anyway

- Conditions under which consensus splits (input that slips past any of
  `docs/SPEC.en.md` §10.2 / §10.3)
- Places where signing or key derivation gives a different answer than another
  implementation
- Any path that recovers a key from a wallet record without the passphrase
- Messages that crash a peer's node, or stall its sync

**Reproduction steps help enormously.** "I think this part might be dangerous"
is fine too. Right now, someone having read the code at all is the most welcome
thing there is.

## There is little to lose at the moment

There is no price and there are very few participants. **In terms of money lost,
this is the safest time there will ever be to break it.** Far better found now
than later.
