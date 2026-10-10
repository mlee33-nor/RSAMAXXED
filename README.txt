================================================================================

        R S A M A X X E D

        Multi-Broker Reverse-Split Arbitrage Automation
        One click buys the play in every account you own.

================================================================================

  RSAMAXXED is a Windows desktop app that runs Reverse-Split Arbitrage (RSA)
  across up to 9 brokerages at the same time. Plays arrive on their own from
  the RSAMAXXED feed. One click (or the automation, if you turn it on) buys
  one share in every linked account, in parallel. When the reverse split
  lands and a broker rounds your fraction up to a whole share, the Exits page
  tells you what to sell and where, and sells it for you.

  Your broker logins stay on your PC. They are used to sign in to that broker
  and nothing else, and are never sent to RSAMAXXED.


CONTENTS
  1.  What is RSA, and how it pays
  2.  The math, with a worked example
  3.  How RSAMAXXED runs the play
  4.  Supported brokers
  5.  Setup (start here)
  6.  Getting your broker credentials
  7.  The app, page by page
  8.  Mirror trading (automatic buying)
  9.  Selling: the Exits page and auto-sell
  10. The plays feed
  11. Trade journal and P/L
  12. Quick start
  13. Updating
  14. Troubleshooting
  15. Notes on results


┌─ 1. WHAT IS RSA, AND HOW IT PAYS ───────────────────────────────────────────
│
│  RSA = Reverse-Split Arbitrage. It turns a quirk in how brokers handle
│  reverse stock splits into small, repeatable profits.
│
│  A company whose stock trades under $1 can be delisted, so it runs a
│  reverse split to lift the price. In a 1-for-20 split, every 20 old
│  shares become 1 new share. If you hold fewer than 20, you are left with
│  a fraction of a share. Many brokers ROUND THAT FRACTION UP to one whole
│  share instead of paying you cash for it.
│
│     BEFORE                          AFTER A 1-FOR-20 REVERSE SPLIT
│     ---------------------------     ----------------------------------
│     Buy 1 share @ $0.25             0.05 share -> rounded UP to 1 share
│     Cost: $0.25                     New share worth about $5.00
│
│                                     Sell it:  $5.00 - $0.25 = $4.75
│
│  One share, one account, one split: $4.75. Small on its own. The round-up
│  is applied per ACCOUNT, though, so the same trade in every account you
│  hold adds up.
│
└──────────────────────────────────────────────────────────────────────────────


┌─ 2. THE MATH, WITH A WORKED EXAMPLE ────────────────────────────────────────
│
│     profit per account  =  entry price x (split ratio - 1)
│                         =  $0.25 x 19  =  $4.75
│
│     profit per play     =  profit per account x accounts that round up
│
│     10 accounts that round up .......  10 x $4.75  =  $47.50
│     20 accounts that round up .......  20 x $4.75  =  $95.00
│
│  That is an illustration, not a forecast. Real plays differ:
│
│     -  the entry price and split ratio are different every time
│     -  not every broker rounds up; some pay the fraction as cash
│     -  the post-split price can drop before you sell
│     -  some plays are cancelled, or the company pays cash instead
│     -  how many qualifying splits appear varies month to month
│
│  The money needed is small: one share of a low-priced stock per account,
│  and it comes back when you sell.
│
│  Results vary. Nothing here is financial advice, and past plays do not
│  promise future ones. You are trading your own accounts at your own risk.
│
└──────────────────────────────────────────────────────────────────────────────


┌─ 3. HOW RSAMAXXED RUNS THE PLAY ────────────────────────────────────────────
│
│     [1]  A reverse split is announced on a low-priced stock.
│            |
│            v
│     [2]  The play arrives in the app from the RSAMAXXED feed and shows
│          up on the Watchlist.
│            |
│            v
│     [3]  BUY: Mirror trading buys it for you automatically, or you buy
│          it in one click on the Trade Desk. One share per account, at
│          every broker you pick, all at once.
│            |
│            v
│     [4]  The split happens. Brokers round your fraction up (or pay cash).
│            |
│            v
│     [5]  SELL: the feed calls the exit and the play moves to SELL NOW on
│          the Exits page. Click Sell, or let auto-sell do it.
│            |
│            v
│     [6]  The trade journal records every fill and Analytics shows your
│          realized profit.
│
└──────────────────────────────────────────────────────────────────────────────


┌─ 4. SUPPORTED BROKERS ──────────────────────────────────────────────────────
│
│  Link any or all of these on the Brokers page. You can add more than one
│  login at each broker (for example yours and a family member's).
│
│    BROKER          HOW THE APP CONNECTS
│    -------------   ------------------------------------------------
│    Chase           Automated Chrome browser
│    Fennel          Broker's own web API
│    Fidelity        Automated Chrome browser
│    IBKR            IBKR's official API, through IB Gateway on this PC
│    Public          Public's official API (secret token)
│    Robinhood       Broker's own web API
│    Schwab          Automated Firefox browser (installed by INSTALL.bat)
│    SoFi            Automated Chrome browser
│    Wells Fargo     Automated Chrome browser
│
│  One login at Chase, Fidelity, Schwab, SoFi and Wells Fargo covers every
│  brokerage account under that login.
│
│  The browser brokers run out of sight by default: no windows pop up on
│  your desktop while the app works.
│
└──────────────────────────────────────────────────────────────────────────────


┌─ 5. SETUP (START HERE) ─────────────────────────────────────────────────────
│
│  You need: a Windows 10 or 11 PC, an internet connection, and Google
│  Chrome if you will use Chase, Fidelity, SoFi or Wells Fargo (Microsoft
│  Edge, which comes with Windows, works as a fallback).
│
│  STEP 1  Get the files
│     Download the ZIP from GitHub (green "Code" button -> Download ZIP)
│     and unzip it somewhere permanent. C:\RSAMAXXED is the best choice:
│     avoid Documents and the Desktop, which OneDrive syncs on many PCs,
│     and any other folder OneDrive or Google Drive syncs. Do not run it
│     from inside the ZIP; INSTALL.bat stops and says so if you try.
│
│  STEP 2  Double-click INSTALL.bat (once)
│     It finds Python (installing Python 3.13 for you if needed), installs
│     everything the app needs, downloads the browser Schwab uses, creates
│     your settings file (.env) and puts an RSAMAXXED icon on your desktop.
│     It takes a few minutes. Wait for "Done".
│
│     Windows may warn you, because the file came from the internet:
│        "Windows protected your PC"  ->  click "More info"
│                                     ->  click "Run anyway"
│     This happens once. INSTALL.bat then clears the "downloaded from the
│     internet" mark from everything else in the folder, so RSAMAXXED.bat
│     and the rest do not ask again.
│
│  STEP 3  Start the app
│     Double-click the RSAMAXXED icon on your desktop (or RSAMAXXED.bat in
│     the folder). If it says it could not start, run INSTALL.bat again.
│
│  STEP 4  Connect your brokers
│     Open the Brokers page. Each broker has a card with the fields it
│     needs (see section 6 for where to find each one).
│        -  Type your login in, then click Save. Save writes it to the .env
│           file in the app's folder, on this PC only.
│        -  Click "+ Add login" for a second login at the same broker. The
│           optional tag is just a nickname so you can tell logins apart.
│        -  Click Bootstrap. The app signs in and lists your accounts. It
│           reports "connected" with the number of accounts, or why it
│           failed.
│     The first sign-in at a broker may ask for a code (text, email or
│     an approve-on-your-phone prompt). The app shows a box on screen to
│     type it into, and says so in a yellow bar. After that, sessions are
│     remembered in the sessions folder, so you are not asked every time.
│
│  STEP 5  The plays are already on
│     Nothing to sign up for, no password, no key. The feed downloads on
│     launch and refreshes every hour. An empty Watchlist just means no
│     plays are open right now. The status bar at the bottom shows when
│     the feed last arrived.
│
└──────────────────────────────────────────────────────────────────────────────


┌─ 6. GETTING YOUR BROKER CREDENTIALS ────────────────────────────────────────
│
│  A note on "TOTP secret". Some brokers let you use an authenticator app
│  (Google Authenticator, Microsoft Authenticator, Authy...) for two-step
│  sign-in. When you turn that on, the broker shows a QR code. Choose the
│  option under it such as "Can't scan?" or "Enter key manually" and it
│  shows a long code of letters and numbers: that is the TOTP secret.
│  Paste it into RSAMAXXED AND add it to your authenticator app as usual.
│  With it, the app can make the 6-digit codes itself. Treat it like a
│  password. If authenticator 2-step is already on, you usually have to
│  turn it off and on again to see the key.
│
│  CHASE
│     Your chase.com USERNAME (not your email address) and password.
│     Chase silently rejects an email address here. If Chase sends a
│     push, the app tells you to approve it in the Chase app. If Chase
│     wants a code typed into its own page, the app brings the Chase
│     browser window to the front and puts up a notice: type the code
│     into that window and press Next. You have about 3 minutes.
│
│  FENNEL
│     Just your Fennel email address; there is no password. Fennel emails
│     you a code at sign-in; type it into the app when asked.
│
│  FIDELITY
│     Username, password, and (optional but recommended) the TOTP secret.
│     With the secret, sign-in needs nothing from you. Without it, the app
│     asks for the code texted to you, or asks you to approve the sign-in
│     in the Fidelity app.
│
│  PUBLIC
│     A personal API secret token, not your password. On public.com, open
│     your account settings, find the API section (under Security) and
│     generate a secret key. Copy it into the Secret token field. No codes
│     are ever needed. One token per Public login.
│
│  ROBINHOOD
│     Username (email) and password. On first sign-in Robinhood usually
│     sends an approval request to your phone: open the Robinhood app and
│     tap Approve. If it asks for a texted or emailed code instead, the app
│     shows a box for it. Wait for the approval rather than retrying;
│     repeated attempts get you rate-limited for a while.
│
│  SCHWAB
│     Username, password, and the TOTP secret. The form says the secret
│     is optional, but a first sign-in without it fails, so treat it as
│     required. Set up authenticator-app 2-step in Schwab's security
│     settings and copy the key as described above.
│
│  SOFI
│     Username, password, and the TOTP secret. Without the secret the app
│     cannot finish SoFi's security check on its own, so treat it as
│     required. If SoFi shows a "Verify you are human" check, the app
│     brings the SoFi browser window to the front and puts up a notice:
│     tick the box in that window (re-enter your password and press
│     Log in if the form was cleared). You have a few minutes.
│
│  IBKR (INTERACTIVE BROKERS)
│     No password goes into RSAMAXXED. You run IB Gateway, IBKR's own
│     small login app, and the app trades through it.
│        1. Install IB Gateway (the "stable" version) from
│           https://www.interactivebrokers.com/en/trading/ibgateway-stable.php
│        2. Open it, choose IB API, and log in with your IBKR username
│           (approve the 2FA on your phone as usual). Choose Live or
│           Paper Trading.
│        3. In Gateway: Configure -> Settings -> API -> Settings:
│             Enable ActiveX and Socket Clients ........ ON
│             Read-Only API ............................ OFF
│             Allow connections from localhost only .... ON
│             Socket port ...... 4001 for live, 4002 for paper
│           Click OK.
│        4. On the Brokers page enter that port in the IBKR card and
│           Save. Leave host and client ID blank. Click Bootstrap.
│     Gateway must be open and logged in whenever the app trades at
│     IBKR, and IBKR logs it out once a day: log back in when it asks.
│     OTC / pink-sheet names need IBKR's penny-stock trading permission
│     (Client Portal -> Settings -> Trading Permissions -> Stocks); without
│     it IBKR refuses those orders and the app shows IBKR's reason.
│     Whole shares only. A second IBKR username needs a second Gateway on
│     its own port ("+ Add login").
│
│  WELLS FARGO
│     Username and password. At sign-in Wells Fargo usually sends an
│     approval to your phone (approve within about 2 minutes). If that
│     times out, the app switches to a texted code and asks you for it.
│
└──────────────────────────────────────────────────────────────────────────────


┌─ 7. THE APP, PAGE BY PAGE ──────────────────────────────────────────────────
│
│  COMMAND CENTER  (home)
│    Net realized profit, the RSA pipeline (pick -> buy -> split -> sell),
│    top movers among current plays, broker status with "Refresh All",
│    the current plays (Quick Picks / Partial / Purchased) and a short
│    Sell now / Holding / Closed summary.
│
│  WATCHLIST
│    Every open play from the feed, with live price, change and a small
│    chart where a public quote exists (many tiny stocks have none), and a
│    marker once you have bought it. "Add Symbol" pins an extra ticker.
│
│  TRADE DESK
│    Buy or sell by hand. Choose BUY or SELL, type the ticker and quantity,
│    pick broker chips, and click Execute. Results appear per account as
│    they come in. "Dry Run" builds the order without sending it. Any
│    quantity over 5 shares per account asks you to confirm first.
│
│  MIRROR
│    A log of everything the automation bought for you, run by run, with
│    per-broker results, and every feed check with what it skipped and
│    why.
│
│  EXITS
│    Where selling happens. The board groups plays into SELL NOW (exit
│    called, you still hold shares), FRACTIONAL, HOLDING and CLOSED, with
│    the auto-sell controls at the top. See section 9.
│
│  INVEST
│    Optional: put idle cash in your broker accounts into ETFs. Pull your
│    balances, pick an ETF and an amount per account, review, then buy.
│    Whole shares only, the same quantity on every account at a broker;
│    an account that can't afford it sits the round out. Has its own Dry
│    run and a confirm step. Holdings are tracked on the page.
│
│  ANALYTICS
│    Realized profit and performance: cumulative P/L, profit by ticker,
│    volume by broker, monthly P/L and more, plus trade tables, a trade
│    simulator, and CSV export of your trade history.
│
│  AUTOMATION
│    Turn Mirror trading on or off and choose its brokers and age limit
│    (section 8). The Alert Feed card needs nothing from you; plays
│    import themselves.
│
│  BROKERS
│    Enter logins, Save, Bootstrap (section 5, step 4). Also the optional
│    RSAMAXXED Cloud card, which links this PC to your web dashboard on
│    rsamaxxed.com (it syncs P/L and positions; never your broker logins).
│
│  ACTIVITY
│    A live log of every sign-in, order and alert, a progress strip while
│    a batch is running, and "Retry failed accounts".
│
│  Also: Ctrl+K opens a quick search (jump to a page, look up or trade a
│  ticker), Ctrl+1 ... Ctrl+9 jump between pages, Ctrl+R refreshes. The
│  bell in the top bar collects notifications. The app version is shown
│  at the bottom of the left sidebar (for example v1.0.1).
│
└──────────────────────────────────────────────────────────────────────────────


┌─ 8. MIRROR TRADING (AUTOMATIC BUYING) ──────────────────────────────────────
│
│  Mirror trading buys new plays for you, so you don't have to be at the
│  screen when an alert lands.
│
│     New play in the feed:  buy 1 share
│              |
│      +-------+-------+-------+-------+-------+-------+ ...
│      v       v       v       v       v       v
│    Robin  Fidelity Chase  Schwab  Wells   SoFi   ...   (brokers you picked)
│
│  How it behaves:
│     -  It is OFF on a fresh install. Turn it on in Automation: pick the
│        broker chips to use, then "Enable Mirror Trading" and confirm.
│        It stays on across restarts until you turn it off.
│     -  It checks for new plays on weekdays during market hours (about
│        once an hour, 9:45 to 3:45 Eastern) and right after new plays
│        arrive. Checks missed while the PC was asleep run when it wakes,
│        but never after 4pm.
│     -  It buys standard alerts only. Conditional and OTC plays are
│        skipped, with the reason shown on the Mirror page.
│     -  It skips plays older than your age limit (default 2 days), and
│        skips any broker that already holds the stock.
│     -  1 share per account, one play at a time, with a short pause
│        between plays.
│     -  These are REAL orders; there is no dry run here. Turning it off
│        cancels anything still queued, but not orders already sent.
│     -  It does not retry failures. They are listed under "Needs
│        attention" with a shortcut to trade them by hand.
│
│  The app must be open for mirror trading to run.
│
└──────────────────────────────────────────────────────────────────────────────


┌─ 9. SELLING: THE EXITS PAGE AND AUTO-SELL ──────────────────────────────────
│
│  After a split, each account ends up one of three ways:
│
│     ROUND-UP   a whole share      sell 1 share wherever you hold it
│     FRACTION   part of a share    only Public, Robinhood and SoFi keep
│                                   fractions; sell the balance there
│     CASH       paid out already   nothing to do (the other seven
│                                   brokers settle fractions as cash)
│
│  The Exits page knows which is which. When the feed calls an exit, the
│  play moves to SELL NOW.
│
│  SELLING BY HAND
│     Click Sell on a row. The app reads your real balance from each
│     broker, then shows exactly what it will sell, where, and which
│     brokers it is leaving out and why (cash-in-lieu, nothing held).
│     Click "Sell at N brokers" to send it. Tick "Dry run" first if you
│     want to build the order without sending anything. "Open in Desk"
│     copies it to the Trade Desk instead.
│
│  AUTO-SELL
│     The Auto-sell card at the top of Exits sells SELL NOW plays for you.
│     -  It starts DISARMED. "Arm auto-sell" turns it on.
│     -  Dry run is ON by default, so at first it only shows what it
│        would do. Untick Dry run for real orders; the status pill then
│        reads "ARMED · LIVE ORDERS".
│     -  "Fractionals too" also sells leftover fractions.
│     -  Market hours only; anything found after hours waits for the open.
│     -  It reads live holdings before every order, never sells the same
│        play twice, handles at most 4 plays per batch (the rest wait for
│        you, with a notification) and tries a play up to 3 times.
│     -  The app must be open for it to run.
│
└──────────────────────────────────────────────────────────────────────────────


┌─ 10. THE PLAYS FEED ────────────────────────────────────────────────────────
│
│  The app downloads plays from rsamaxxed.com automatically: no account,
│  no password, nothing to join or set up. Three things arrive, on launch
│  and then every hour while the app is open:
│
│     BUYS    new plays to open        -> Watchlist and Mirror trading
│     BOARD   what each split did      -> Exits (round-up, fraction, cash)
│     EXITS   when and where to sell   -> Exits SELL NOW
│
│  If a download fails the app retries on its own, and the status bar
│  turns yellow when the feed is stale.
│
│  Linking this PC to an rsamaxxed.com account (Brokers page, RSAMAXXED
│  Cloud) is optional and only adds the web dashboard. It sends a device
│  name and a random id; no broker login ever leaves the PC.
│
└──────────────────────────────────────────────────────────────────────────────


┌─ 11. TRADE JOURNAL AND P/L ─────────────────────────────────────────────────
│
│  Every share RSAMAXXED buys or sells is recorded in trades.json in the
│  app folder: broker, account, buy or sell, ticker, quantity, price and
│  time. Shares you bought elsewhere are left out, so the numbers only
│  cover this tool's trades.
│
│  Profit is counted when you SELL (realized profit). The app does not
│  show paper gains on open plays, because until the split settles and
│  you sell, there is no real profit to show.
│
│  trades.json is the one file nothing can rebuild. Back it up now and
│  then, and keep it when you update (section 13).
│
└──────────────────────────────────────────────────────────────────────────────


┌─ 12. QUICK START ───────────────────────────────────────────────────────────
│
│     1.  Run INSTALL.bat once, then open RSAMAXXED from the desktop.
│     2.  Brokers page: enter a login, Save, Bootstrap. Repeat per broker.
│     3.  Command Center: "Refresh All". Green dots = ready.
│     4.  Buy: turn on Mirror trading (Automation), or use the Trade Desk
│         to buy 1 share of a Watchlist play at all your brokers.
│     5.  Watch the Activity page confirm each account filled.
│     6.  After the split, sell from Exits (or arm auto-sell).
│     7.  See your realized profit on the Command Center and Analytics.
│
└──────────────────────────────────────────────────────────────────────────────


┌─ 13. UPDATING ──────────────────────────────────────────────────────────────
│
│  Check the version at the bottom of the left sidebar, and compare it
│  with the latest release on GitHub:
│     https://github.com/mlee33-nor/RSAMAXXED/releases
│  The current version is v1.0.1. Close RSAMAXXED before updating.
│
│  IF YOU INSTALLED WITH GIT
│     1.  In the app folder run:   git pull
│         Your .env, trades.json and other personal files are not
│         tracked by git, so they are left alone.
│     2.  Double-click INSTALL.bat again. It is safe to re-run at any
│         time: it installs any add-ons the update needs and never
│         touches your settings or trades.
│
│  IF YOU INSTALLED FROM THE ZIP
│     1.  Download the new ZIP and unzip it to a NEW folder.
│     2.  From your OLD folder, copy these into the new one:
│            .env                    your broker logins
│            every .json file in     trades.json (your trade history)
│            the main folder         and the app's saved state; the ZIP
│                                    has none in its main folder, so
│                                    nothing of the new version is
│                                    overwritten
│            the sessions folder     saved broker sign-ins
│            the logs folder         trade results the app reads back
│                                    (logs	rade_results.log) and your
│                                    activity history -- keep it
│     3.  Double-click INSTALL.bat in the NEW folder. It is quick when
│         nothing changed, updates anything that did, and points the
│         desktop icon at the new folder.
│     4.  Start the app and check that your trades and brokers are there,
│         then delete the old folder.
│
│  Running INSTALL.bat again is always safe: it never changes your .env
│  or your trade history.
│
└──────────────────────────────────────────────────────────────────────────────


┌─ 14. TROUBLESHOOTING ───────────────────────────────────────────────────────
│
│  The app doesn't open / "RSAMAXXED could not start"
│     Run INSTALL.bat again and read any error it shows.
│
│  "Windows protected your PC"
│     More info -> Run anyway. It only appears for downloaded files.
│
│  A broker fails to connect
│     Check the Activity page for the reason. Common ones:
│        -  Chase: use your username, not your email.
│        -  Schwab or SoFi: add the TOTP secret (section 6).
│        -  Robinhood: approve on your phone, and don't retry quickly.
│        -  Schwab "Executable doesn't exist": run INSTALL.bat again.
│     To watch the browser brokers work, add RSA_BACKGROUND=false to .env
│     and restart the app.
│
│  The Watchlist is empty
│     Usually just no open plays right now. The status bar shows when the
│     feed last arrived.
│
└──────────────────────────────────────────────────────────────────────────────


┌─ 15. NOTES ON RESULTS ──────────────────────────────────────────────────────
│
│  RSAMAXXED automates the clicking. It does not guarantee a profit. What
│  a play earns depends on the split ratio and post-split price, how each
│  broker handles fractions, how many accounts you link, and how many
│  qualifying splits appear. Brokers can reject orders, change their
│  rules, or restrict accounts. Only trade money you can afford to lose,
│  and check your broker statements.
│
│  This software is not financial advice.
│
└──────────────────────────────────────────────────────────────────────────────

================================================================================
  RSAMAXXED  -  pick it, mirror it, round it up.
================================================================================
