# Why Confidant exists

*(The thesis, in one page.)*

## The shift

CRMs were built for businesses, because a business has many hands on each
relationship — sales, support, billing — and the relationship has to survive
the person. A CRM is the shared memory that lets a company hold a
relationship no single employee could hold alone.

That condition — *many hands on one set of relationships* — is no longer
unique to businesses. AI agents give a single person many hands. But agents
often keep their own memories. Tell one how you know a friend, switch
tools, and you may have to tell the story again. Repeating that onboarding
discourages trying another agent and gives the current one an accidental
hold on your history.

Confidant keeps the record with you. Each agent you connect can work from
the same account of the people in your life, subject to the boundaries you
set. You still have to connect and instruct each agent; you do not have to
re-create the relationship record inside each one.

That is Confidant: relationship memory for one person and their agents.

## Not a CRM, not a PKM

- **Not a CRM.** CRMs are built around a sales pipeline and a tenant owned by
  a company. Confidant is built around *your* relationships, owned by *you*.
- **Not a PKM.** A PKM optimizes for your notes and ideas. Confidant optimizes
  for *who you know and where things stand with them* — the people, and the
  places and things they connect through.

The closest name is **relationship memory**: a system of record for the
relationships in your life, focused by default on people, then places, then
things.

This focus matters. A general agent memory may remember preferences, tasks,
or facts about a workspace. A relationship has a person at its center: how
you met, what you share, what changed, and what you last did together. A
person is not a sales account or a document. Places and things matter
because they connect back to people.

## Portability and packs

The record is plain-text files in a Git repository you control. You can
read, diff, back up, and move those files without depending on one model,
agent, or hosted memory service. A new agent can be pointed at the same
vault. Portability is more than an export button: the working copy is
already yours.

The built-in personal pack provides the vocabulary for people, places,
things, and moments between them. Schema packs can add a different
vocabulary and checks without turning every relationship into a sales
pipeline. The core remains small; the operator chooses which domains to
model.

## What it assumes

1. **One operator, many agents.** You are the owner; your agents are staff.
   There is no second human whose privacy you must protect from — only the
   line between you and your tools.
2. **The human↔agent boundary is the real one.** `no-ai` is the load-bearing
   rule: some things you know are for you, not for your agents. It is
   enforced in code, not by convention.
3. **You own the record.** Plain-text files in a Git repo you control, on a
   disk you control. No Confidant server or account. You can change agents
   without moving your relationship history out of their private memory.

## Where it's going

The next boundary is the household: a handful of people, each with their own
agents, running a shared life the way a small business runs its operations.
That is deliberately out of scope today — single operator first — but it is
the direction: separate vaults that interoperate, not one shared vault.
