================================================================================

        R S A M A X X E D

        Multi-Broker Reverse-Split Arbitrage Automation
        Set it up once. Target ~$600/month in round-up profit. Hands-off.

================================================================================

  RSAMAXXED is a desktop app that runs Reverse-Split Arbitrage (RSA) for you
  across 10 brokerages at the same time. You pick the plays, hit one button,
  and it buys the position in every linked account in parallel. When the
  reverse splits land and your shares get rounded up, you sell and pocket
  the difference. The whole loop is automated behind a single GUI.


CONTENTS
  1.  What is RSA, and how it pays
  2.  The monthly math (~$600)
  3.  How RSAMAXXED runs the play
  4.  Feature overview
  5.  Supported brokers
  6.  The GUI — tab by tab
  7.  Mirror trading
  8.  The picks feed
  9.  Trade journal & P/L tracking
  10. Setup
  11. Quick start
  12. Notes on results


┌─ 1. WHAT IS RSA, AND HOW IT PAYS ───────────────────────────────────────────
│
│  RSA = Reverse-Split Arbitrage. It turns a quirk of how brokers handle
│  reverse stock splits into repeatable profit.
│
│  When a company runs a reverse split — say 1-for-10 — every 10 old shares
│  become 1 new share. Hold an amount that does not divide evenly and you
│  are left with a fractional share. Here is the edge: many brokers ROUND
│  THAT FRACTION UP to a whole share instead of paying you cash for it.
│
│     BEFORE                      AFTER A 1-FOR-10 REVERSE SPLIT
│     -----------------------     -----------------------------------
│     Buy 1 share @ ~$0.80        0.1 share -> rounded UP to 1 share
│     Cost: ~$0.80                New share worth ~$8.00+
│                                 Net round-up gain: several dollars
│
│  One share, one broker, one split. Small. But run it as 1 share in
│  every account, across 10 brokers, on every qualifying split — and the
│  small numbers stack into real monthly income.
│
└──────────────────────────────────────────────────────────────────────────────


┌─ 2. THE MONTHLY MATH (~$600) ───────────────────────────────────────────────
│
│  The model is simple multiplication:
│
│     profit  =  round-ups per split  x  brokers linked  x  splits / month
│
│  A worked example:
│
│     per round-up gain ........ $8  - $25   (varies by post-split price)
│     brokers linked ........... 10
│     qualifying splits / mo ... 3  - 6
│
│     low  end:  $8  x 10 x 3  =  $240
│     mid  band: $15 x 10 x 4  =  $600     <-- the target
│     high end:  $25 x 10 x 5  =  $1,250
│
│  ┌────────────────────────────────────────────────────────────────────┐
│  │  TARGET:  ~$600 / month  for roughly 10 minutes of work per play.   │
│  └────────────────────────────────────────────────────────────────────┘
│
│  Capital required is tiny: one share of a sub-$5 stock per broker.
│  A full month of plays typically ties up well under $200 at a time,
│  and that capital comes back the moment you sell.
│
└──────────────────────────────────────────────────────────────────────────────


┌─ 3. HOW RSAMAXXED RUNS THE PLAY ────────────────────────────────────────────
│
│  The full cycle, start to finish:
│
│     [1]  A reverse split gets announced on a low-priced stock.
│            |
│            v
│     [2]  It lands in the picks feed (synced) or you add it yourself.
│            |
│            v
│     [3]  Open the Trade tab, select the ticker, pick your brokers.
│            |
│            v
│     [4]  One click -> RSAMAXXED buys the position in EVERY linked
│          broker at once (mirror trading, run in parallel).
│            |
│            v
│     [5]  The reverse split executes. Brokers round your holdings up.
│            |
│            v
│     [6]  Holdings tab flags the position; you sell across all brokers.
│            |
│            v
│     [7]  Trade journal logs every fill and shows realized P/L.
│
│  Steps 3-4 are the only ones that need you, and they take a minute.
│
└──────────────────────────────────────────────────────────────────────────────


┌─ 4. FEATURE OVERVIEW ───────────────────────────────────────────────────────
│
│   +  Ten brokers, one window — no juggling tabs and logins.
│   +  Mirror trading — one order replicated across every linked account.
│   +  Parallel execution — all brokers fire at once, not one by one.
│   +  Synced picks feed — a shared, dated watchlist of reverse-split plays.
│   +  Reverse-split alerts — qualifying positions highlighted automatically.
│   +  Live P/L — realized profit tracked per position, green/red coded.
│   +  Trade journal — every share this tool buys or sells is logged.
│   +  One-screen dashboard — invested, value, P&L, broker health at a glance.
│   +  Dark desktop GUI — no terminal needed for day-to-day use.
│
└──────────────────────────────────────────────────────────────────────────────


┌─ 5. SUPPORTED BROKERS ──────────────────────────────────────────────────────
│
│  All ten link from the Accounts tab and run side by side.
│
│    BROKER          CONNECTION
│    -------------   ------------------------------------------------
│    Robinhood       API
│    Fidelity        Automated browser session
│    Chase           Automated browser session
│    Schwab          API
│    Wells Fargo     Automated browser session
│    SoFi            Automated browser session
│    Fennel          API
│    Public          API
│    BBAE            API
│    DSPAC           API
│
│  More linked accounts = more round-ups per split = higher monthly total.
│  Link every broker you can to hit the $600 target comfortably.
│
└──────────────────────────────────────────────────────────────────────────────


┌─ 6. THE GUI — TAB BY TAB ───────────────────────────────────────────────────
│
│  DASHBOARD
│    Metric cards for total invested, current value, and net P&L. Broker
│    status dots show which accounts are live. "Refresh All" re-pulls
│    every broker in one go.
│
│  HOLDINGS
│    A live table of every position this tool opened, with running P/L
│    in green or red. Positions tied to an upcoming reverse split are
│    highlighted so you know exactly what is ready to sell.
│
│  TRADE
│    The control room. Pick a ticker, choose BUY or SELL, select brokers
│    by chip (only linked brokers show), and fire. Execution runs across
│    all selected brokers in parallel.
│
│  ACCOUNTS
│    Per-broker credential fields. Save to .env, then Bootstrap to
│    establish the session. Do this once per broker.
│
│  LOGS
│    A running activity log of every action — useful for confirming a
│    multi-broker order all went through.
│
└──────────────────────────────────────────────────────────────────────────────


┌─ 7. MIRROR TRADING ─────────────────────────────────────────────────────────
│
│  Mirror trading is the core of RSAMAXXED. One order is cloned to every
│  broker you select and submitted at the same time:
│
│     YOU:  Buy 1 share UCAR
│              |
│      +-------+-------+-------+-------+-------+-------+-------+ ...
│      v       v       v       v       v       v       v
│    Robin  Fidelity Chase  Schwab  Wells   SoFi   Fennel  ...
│      |       |       |       |       |       |       |
│      +-------+-------+-------+-------+-------+-------+-------+
│                            |
│                            v
│              10 identical positions, one click
│
│  That is what turns a few-dollar round-up into a few-hundred-dollar one.
│
└──────────────────────────────────────────────────────────────────────────────


┌─ 8. THE FEED — WHERE THE PLAYS COME FROM ───────────────────────────────────
│
│  You do not hunt for splits and you do not need Discord. Put your
│  plays password in .env and three streams arrive on their own,
│  refreshed every hour:
│
│     RSAMAXXED_PLAYS_KEY=your-password
│
│     BUYS    the plays to open       -> Watchlist, and Mirror Trading
│     BOARD   what each split DID     -> Exits
│     EXITS   what got sold, where    -> the sell-alert card
│
│  It is the same password that opens rsamaxxed.com/plays in a browser,
│  where the whole board also lives: what is open, what exited, what
│  every past split ended in, and what that record is worth at your
│  account count.
│
│  The BOARD is the one that matters most and the one you cannot work
│  out yourself. After a reverse split your position either rounded up
│  to a whole share, came back as a fraction, or was paid out as cash —
│  and which of those happened decides whether there is anything left
│  to sell at all. See section 8b.
│
│  No account is required to receive any of it, and nothing is stored
│  about you: the password identifies the subscription, not you. Linking
│  a device is optional and only adds the cloud dashboard — it sends a
│  device name and a random id, and no broker credential ever leaves
│  the machine.
│
└──────────────────────────────────────────────────────────────────────────────


┌─ 8b. FRACTIONS, ROUND-UPS, AND WHO PAYS WHICH ──────────────────────────────
│
│  Only THREE brokers hand back a fractional share after a split:
│
│     Public      Robinhood      SoFi
│
│  The other seven settle the fraction as cash. There is nothing left in
│  those accounts to sell, and an order sent to them is rejected every
│  time. The Exits page already knows this — a fractional play is routed
│  only to the three, and the rest are listed as "cash-in-lieu at ..."
│  so it is obvious why they were left out.
│
│  A round-up is the opposite: a whole share exists, and any broker
│  holding it can sell it.
│
│     ROUND-UP  ✅   sell 1 share      every broker you hold it at
│     FRACTION  🧩   sell the balance  Public / Robinhood / SoFi only
│     CASH      💵   nothing to do     already settled to cash
│
│  Hit Sell on an Exits row and the terminal reads the real balance from
│  each broker, shows you exactly what it will send where, and waits for
│  you to confirm. Tick "Dry run" to build the whole order against your
│  live sessions without submitting anything.
│
└──────────────────────────────────────────────────────────────────────────────


┌─ 9. TRADE JOURNAL & P/L TRACKING ───────────────────────────────────────────
│
│  Every share RSAMAXXED buys or sells is written to the trade journal
│  (trades.json) — broker, account, side, symbol, quantity, fill price,
│  timestamp. Pre-existing holdings you did not buy through the tool are
│  left out, so the numbers stay clean.
│
│  After a successful buy the tool auto-pulls the actual fill price from
│  the broker, which is what powers the live P/L on the Holdings tab and
│  the realized-profit total on the Dashboard. You always know exactly
│  how much each play made.
│
└──────────────────────────────────────────────────────────────────────────────


┌─ 10. SETUP ─────────────────────────────────────────────────────────────────
│
│  Requirements: Python 3.13 on Windows.
│
│     1.  Install dependencies:
│            pip install -r requirements.txt
│
│     2.  Launch the app:
│            RSAMAXXED.bat
│         (or run app.py directly for the GUI, or runner.py for CLI)
│
│     3.  TURN ON THE PLAYS. Copy .env.example to .env and set the one
│         line that makes alerts arrive:
│
│            RSAMAXXED_PLAYS_KEY=the password you were given
│
│         No account, no sign-up, no pairing code, no Discord. The
│         terminal downloads the buy alerts, the exits and the round-up
│         (fractional) board on launch, then refreshes every hour while
│         it is open.
│
│         Without that line the Watchlist stays empty and the status bar
│         bottom-right never shows a feed arrival — a missing or wrong
│         password is the usual cause, not a broken install.
│
│     4.  CONNECT YOUR BROKERS. Copy .env.example to .env and fill in
│         only the brokers you use, or enter them in the Brokers tab and
│         click Save. Then Bootstrap each one to start its session.
│
│     5.  Open the Dashboard and hit Refresh All. Green status dots
│         mean a broker is linked and ready.
│
│  Credentials live in a local .env file and are used to log in to that
│  broker and nothing else — none of them are ever sent to RSAMAXXED
│  Cloud. Sessions are cached locally so you do not log in from scratch
│  every time.
│
└──────────────────────────────────────────────────────────────────────────────


┌─ 11. QUICK START ───────────────────────────────────────────────────────────
│
│     1.  Pick a play from the picks feed (or add your own ticker).
│     2.  Trade tab -> select the ticker -> BUY -> select all brokers.
│     3.  Fire. Watch the Logs tab confirm every broker filled.
│     4.  Wait for the reverse split to execute.
│     5.  Holdings tab highlights the rounded-up position.
│     6.  Trade tab -> SELL across all brokers -> done.
│     7.  Check realized P/L on the Dashboard.
│
└──────────────────────────────────────────────────────────────────────────────


┌─ 12. NOTES ON RESULTS ──────────────────────────────────────────────────────
│
│  The ~$600/month figure is a target, not a promise. Actual return per
│  play depends on:
│
│     -  the split ratio and the post-split price
│     -  how each broker handles fractional shares at split time
│     -  how many brokers you have linked
│     -  how many qualifying splits show up that month
│
│  Link more brokers and run every clean pick in the feed to push your
│  monthly number toward — and past — the $600 mark.
│
└──────────────────────────────────────────────────────────────────────────────

================================================================================
  RSAMAXXED  —  pick it, mirror it, round it up.
================================================================================
