# Start here: scan a website for exposed patient data

No coding needed. This takes three double-clicks and one form.

## Before you start

- **Permission.** Only scan a website you own, or one whose owner has given you
  written permission. Scanning someone else's site without permission can be illegal.
- **A Windows computer** with an internet connection and about 2 GB of free space.

## Step 1: install Python (once)

1. Open <https://www.python.org/downloads/release/python-3119/>.
2. Scroll down and download the **Windows installer, 64-bit**.
3. Run it and click **Install Now**. The default options are fine.

## Step 2: set up the scanner (once)

Double-click **`install.bat`** in this folder. A black window opens, downloads what
the scanner needs (about 1 GB), and says **Setup finished** after 5 to 15 minutes.
Press any key to close it.

## Step 3: open the scanner (every time)

Double-click **`start.bat`**. A black window opens, and your web browser shows the
scanner page. Keep the black window open while you use the scanner; close it when
you are done.

## Step 4: fill in the form

1. **Website address**: the full address, for example `https://portal.example-clinic.org`.
2. Tick **I own this website, or I have written permission**.
3. **Most pages to visit**: leave 200, or use 20 for a quick first look.
4. Press **Start scan**.

That is all you need for a public scan: it looks at what any visitor can see.

### Optional: the logged-in test

This checks whether one patient can open another patient's records, a common and
serious leak. You need two **test** patient accounts on the site (never real
patients' accounts).

1. In Chrome or Edge, log in to the site as test account 1.
2. Press **F12**, click the **Network** tab, and press **F5** to reload.
3. Click the first row, then **Headers**, and scroll to **Request Headers**.
4. Right-click the value next to **cookie:** and copy it.
5. Paste it into **Test account 1 cookie line**.
6. Open a private (incognito) window, log in as test account 2, and repeat for
   **Test account 2 cookie line**.

The scanner finds the record addresses by itself when the site publishes an API
description, which most modern patient portals do. If it reports that none was
found, ask the site's developers for the addresses and fill in the **Advanced**
section.

The cookie lines are used for that one scan and never saved.

### Optional: AI second opinion

Leave this **off** for any site that may hold real patient data, unless your
organisation has approved sending masked snippets to Groq. The scan works fully
without it.

## Step 5: read the results

The page refreshes by itself while the scan runs (usually 10 to 30 minutes for
200 pages). When it finishes you see:

- **How many possible exposures**, by level: *Critical* and *High* need attention first.
- **Open the report**: a table of every finding. Patient values are masked, but
  treat it as a sensitive document anyway.
- **Logged-in access test**: whether account 1 could open account 2's record.
- **Checks**: confirms every finding was re-read from the stored evidence and matched.
- **Results folder**: everything is saved on this computer in your user folder,
  under `PHI-Scans`.

Every finding means *possible PHI exposure, needs compliance review*. It is not a
legal decision that a breach happened. Pass the report to your compliance or
privacy officer.

## If something goes wrong

| What you see | What to do |
|---|---|
| "Python 3.11 is not installed" | Do step 1, then double-click `install.bat` again. |
| "Setup did not finish" | Check the internet connection and run `install.bat` again. |
| "The scanner is not set up yet" | Double-click `install.bat` first. |
| "The website could not be reached" or "No pages could be read" | Check the address opens in your browser on this computer. |
| "The scan stopped early: server asked us to slow down" | The site limited us. Try again later, or with fewer pages. |
| "The scanner's browser is missing" | Double-click `install.bat` again. |
| The browser did not open | Open <http://127.0.0.1:8765/> yourself while the black window is open. |

## What it does not do

- It never fills in or submits forms, never logs in with a password, and never
  changes anything on the site.
- It does not read text inside images.
- It only finds pages that are linked from other pages, listed in the site map, or
  at well-known addresses. A file nothing links to can still be missed.
- A clean result does not prove a site is clean.
