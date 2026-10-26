# 09 · Experience

People use mail in very different ways. firstread has to be right for each of them without asking
anyone to configure anything, and has to be invisible when it has nothing worth saying.

## How people use mail

| who | how they work | what they want from firstread | what would annoy them |
|---|---|---|---|
| **the processor** | inbox zero, acts on everything | what needs action, what is waiting on whom | noise in the inbox; tags they did not ask for |
| **the piler** | thousands unread, searches when needed | the few important things surfaced; scams kept away | being told to "clean up" |
| **the filer** | own folder structure, years old | suggestions that follow *their* folders | imposed categories |
| **the small business owner** | invoices, quotes, customers, suppliers, all in one mailbox | invoice and payment fraud stopped; customer requests never lost; invoices findable | a real customer filed as junk |
| **the shared mailbox** (`info@`, `support@`) | several people, high volume, lots of spam | routing by intent (quote request, complaint, invoice); spam gone | personal-style learning from one person's habits |
| **the POP3 / classic-client user** | often older setups, downloads everything | scams clearly marked in the Subject; nothing lost | mail disappearing into a folder they cannot see |
| **the phone-first user** | reads on mobile, notifications matter | fewer pings for mail that can wait | missing a ping that mattered |
| **the alert-heavy technical user** | server alerts, cron mail, monitoring | alerts recognised as alerts, never junked | alerts filed with marketing |
| **the privacy-minded user** | wants control | transparency, an off switch, export and erase | anything that looks like profiling |
| **the forwarder** | forwards to another provider | protection that survives forwarding (headers travel along) | broken authentication on the other side |

## Modes

Each mailbox has a mode. firstread picks one from the mailbox's own history during backfill (folder
use, read habits, volume, protocol); the user can change it with one tap in the digest or webmail.

| mode | inbox | folders | tags | warnings | default for |
|---|---|---|---|---|---|
| **Quiet** | everything except junk | Junk only | none | scams only | pilers, privacy-minded, unknown |
| **Focused** | people and things that need you | Junk, *Later* (bulk you rarely read) | a few | scams, payment fraud | phone-first, processors |
| **Sorted** | people and things that need you | Junk, Later, plus the user's own folders by suggestion | yes | scams, payment fraud | filers |
| **Business** | customers, suppliers, colleagues | Junk, Later, invoices | money, customers, orders | scams, payment fraud, bank-detail changes | small business, organisations |
| **Team** | by intent for the team | Junk, plus intent folders | intent | scams, payment fraud | shared mailboxes |
| **Classic (POP3)** | everything except high-confidence junk | Junk at a strict threshold | n/a | Subject prefix | POP3 mailboxes |

Moving bulk mail out of INBOX into *Later* is also the main lever for phone notifications: clients
typically notify for INBOX only, so fewer pings come for free without any client change (to confirm
per client in the capability matrix).

## What each person sees

**Most of the time: nothing new.** Mail arrives sorted the way they already sort. No banner, no
prefix, no extra mail.

**When something matters**, one line, plain language (Dutch at B1 level by default, the user's own
language when detected from their Sent mail), one specific reason, one-tap actions:

> **Let op:** je hebt nooit eerder gemaild met dit adres, en het vraagt om een betaling naar een nieuw rekeningnummer.
> [Dit is in orde] [Dit is oplichting]

> **Let op:** dit lijkt van ING te komen, maar is verstuurd vanaf een domein dat 3 dagen oud is.

> **Afwijkend IBAN:** eerdere facturen van Leverancier BV gingen naar een ander rekeningnummer.

Never generic ("this message may be dangerous"). If firstread cannot name the reason, it does not warn.

**The digest** is the one place that works in every client, POP3 included. Off by default for
Quiet, weekly for the others; the first digest asks how often. It contains only sections with
something in them:

- *Tegengehouden*: what was filtered this week, with one-tap rescue; includes a few borderline cases
  on purpose (that is how firstread learns from what it hid)
- *Suggesties*: "You always move mail from X to Projects. Do this automatically?" [Ja] [Nee]
- *Nooit gelezen*: newsletters you have not opened in months, one-tap unsubscribe (RFC 8058)
- *Wacht op antwoord*: threads waiting on you, and on them
- *Facturen*: invoices received, with due dates (Business mode)
- *Beveiliging*: lookalikes of your domain seen this week, bank-detail changes (Business mode)

**In webmail** (where a plugin exists): a reason line on any message ("Waarom?"), corrections per
reason, the overview of subscriptions, invoices and waiting threads, settings, export and erase.

## Rules of the experience

1. **Quiet by default.** Every visible element must earn its place.
2. **Alert budget.** A target number of warnings per user per week; if a mailbox exceeds it, low-severity
   warnings raise their thresholds. Warnings per user per week is a tracked metric.
3. **Specific or silent.** A warning names its reason or does not appear.
4. **Learn, then suggest, never impose.** Patterns become suggestions with one-tap acceptance;
   nothing is silently re-filed based on a guess about preferences.
5. **Everything is undoable** with the action the user would take anyway (move it back, remove the
   tag), and the undo teaches.
6. **The user's structure wins.** Suggestions use the user's folders and names, not ours.
7. **Never lose mail.** POP3 users and Classic mode get stricter filing; everything filtered is in
   the digest.
8. **Notifications are a feature.** Fewer pings for mail that can wait; never fewer for mail that matters.
9. **Transparent and reversible learning.** "Waarom?" on any decision; export and erase what was
   learned; an off switch per mailbox and per organisation.
10. **Accessible.** Banners are plain text first, readable by screen readers, high contrast, short.

## Scenarios

| scenario | what happens |
|---|---|
| A bookkeeper receives an invoice from a regular supplier, sent from the supplier's real (compromised) account, with a new IBAN | authentication passes and the sender is known; bank-detail change fires; banner names the change; Business mode lists it under *Beveiliging*; one tap "Klopt" teaches the new IBAN |
| A 70-year-old POP3 user gets a DigiD phishing mail | lookalike and brand-impersonation fire; Subject gets the prefix; the message stays in the inbox (POP3); after six other mailboxes junk the same campaign, later copies are filed for everyone |
| A developer gets 200 monitoring alerts a day | sender kind "machine / system", never junk; Focused mode keeps them out of the inbox if the user never opens them during the day, which the digest suggests first |
| A team inbox gets a quote request between 50 spam mails | spam filed; the quote request tagged and kept; team feedback trains the organisation scope, not one person's habits |
| A user keeps moving a newsletter from Later back to the inbox | after a couple of moves, the residual head flips for that list; no button pressed |
| A user removes the *money* tag from receipts of one shop three times | tag head residual learns; the next receipt from that shop arrives without the tag |
