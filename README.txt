
TL;DR
-----
The entire Idle Markets codebase — 25,000+ lines — took less than an
hour to extract. The app tries to keep its broker trading code hidden
by pulling it from Discord into memory at runtime and wiping it after.
Problem is the bot token sits in a plain text file, the broker code
on Discord isn't encrypted, and a config file shipped with the app
literally maps out every Discord thread ID and filename for each
broker module. So it was just a matter of reading the token, reading
the config, and hitting Discord's API. Ten requests later — Robinhood,
Fidelity, Chase, Schwab, Wells Fargo, SoFi, Fennel, Public, BBAE,
and DSPAC, all sitting in plain readable Python. The funny part is
there's a whole encryption system built into the app for exactly this.
It's just never been turned on.


WHAT IS THIS
------------
This folder contains all 10 broker automation modules from Idle Markets.
These are the actual Python scripts that log into your brokerage accounts
and place trades.


WHAT'S IN THIS FOLDER
---------------------
  robinhood.py .... 1,138 lines — uses robin_stocks library, API-based
  fidelity.py ..... 2,459 lines — browser automation via Playwright/Firefox
  chase.py ........ 1,529 lines — browser automation via Playwright/Firefox
  schwab.py ....... 1,267 lines — uses schwab_api library, API-based
  wellsfargo.py ... 1,522 lines — browser automation via Playwright/Firefox
  sofi.py ......... 1,467 lines — browser automation via Playwright/Firefox
  fennel.py .......   640 lines — uses fennel_invest_api, API-based
  public.py .......   716 lines — API-based
  bbae.py .........   777 lines — uses bbae_invest_api, API-based
  dspac.py ........   789 lines — uses dspac_invest_api, API-based


OTHER ISSUES FOUND IN THE CODE
------------------------------

Beyond the source code being wide open, there's a bunch of other stuff
that came up after going through the full codebase:

1. The Discord bot token doubles as the encryption key
   In idle_markets.py, if REMOTE_SOURCE_KEY isn't set (and it usually
   isn't), the app falls back to using your DISCORD_TOKEN as the key
   to decrypt broker modules. So the bot token isn't just for Discord
   access — it's also the master decryption key. One secret, two doors.

2. Session files use Python pickle (arbitrary code execution risk)
   Robinhood, BBAE, DSPAC, and Fennel all store login sessions as
   .pickle files under the sessions/ folder. Pickle is a known
   security hazard — if anyone swaps out a pickle file with a
   malicious one, it runs arbitrary code when the app loads it.
   There's no restricted unpickler or any validation.

3. Auto-update trusts one Discord user ID and nothing else
   The entire update system relies on checking if a Discord message
   came from user ID 843194795781914644. No code signing, no hash
   pinning, no certificate check. If that Discord account gets
   compromised, every single user gets a malicious update pushed
   to their machine automatically.

4. The encryption they built is hand-rolled and weak
   remote_cipher.py implements a custom XOR stream cipher with
   SHA256 as the block function. It's not using any standard library
   like AES or ChaCha20. The key derivation is a single SHA256 pass
   with no iteration count — no PBKDF2, no argon2, nothing. A GPU
   can brute-force weak secrets at billions of hashes per second.

5. 2FA codes get sent through Discord in plain text
   When a broker needs a one-time code, the app posts a message to
   your Discord channel asking for it, then reads your reply. That
   means your OTP codes are sitting in Discord message history in
   the clear. Anyone with access to that channel sees them.

6. Some brokers auto-generate TOTP codes from stored secrets
   Schwab, SoFi, and Fidelity can store your TOTP secret in an
   environment variable and auto-generate codes with pyotp. Handy,
   but it means your 2FA is completely bypassed if someone gets
   the env file — they have the seed, they can generate codes
   forever without your phone.

7. SoFi cookies dumped to disk as plain JSON
   sofi.py writes session cookies (including CSRF tokens) to
   sessions/sofi/cookies.json with no encryption and no file
   permissions set. Any process on the machine can read them.

8. SHA256 verification on updates is optional and self-attested
   The auto-updater can check a SHA256 hash, but only if the
   update manifest includes one. The manifest comes from the same
   Discord message as the update itself, so an attacker controls
   both the file and the "expected" hash. It's checking its own
   homework.

9. No unexpected data exfiltration found
   On the positive side — after searching every file for external
   URLs and network calls, all traffic goes exclusively to Discord
   and the brokerage sites. No hidden telemetry, no third-party
   analytics, no data being sent anywhere it shouldn't be.


