# Why Confidant exists

*(The thesis, in one page.)*

## The shift

CRMs were built for businesses, because a business has many hands on each
relationship — sales, support, billing — and the relationship has to survive
the person. A CRM is the shared memory that lets a company hold a
relationship no single employee could hold alone.

That condition — *many hands on one set of relationships* — is no longer
unique to businesses. AI agents are about to give a single person many
hands. Your agents draft the email, remember the birthday, follow up on the
loose thread, and keep the notes — and each one touches the same people you
do. The moment you have more than one agent (plus yourself) working the same
relationships, you have the same problem a business has: you need one memory
that survives the individual, that every hand reads from and writes to, and
that you — not the tools — own.

That is Confidant. It is the CRM, but for a person.

## Not a CRM, not a PKM

- **Not a CRM.** CRMs are built around a sales pipeline and a tenant owned by
  a company. Confidant is built around *your* relationships, owned by *you*.
- **Not a PKM.** A PKM optimizes for your notes and ideas. Confidant optimizes
  for *who you know and where things stand with them* — the people, and the
  places and things they connect through.

The closest name is **relationship memory**: a system of record for the
relationships in your life, focused by default on people, then places, then
things.

## What it assumes

1. **One operator, many agents.** You are the owner; your agents are staff.
   There is no second human whose privacy you must protect from — only the
   line between you and your tools.
2. **The human↔agent boundary is the real one.** `no-ai` is the load-bearing
   rule: some things you know are for you, not for your agents. It is
   enforced in code, not by convention.
3. **You own the memory.** Plain-text files in a git repo you control, on a
   disk you control. No server, no account, no lock-in. You can leave
   tomorrow and take everything with you.

## Where it's going

The next boundary is the household: a handful of people, each with their own
agents, running a shared life the way a small business runs its operations.
That is deliberately out of scope today — single operator first — but it is
the direction: separate vaults that interoperate, not one shared vault.
