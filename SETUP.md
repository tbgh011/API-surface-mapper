# Setup guide

This walks you through running the **server engine** on your own machine, from
nothing installed to your first scan. It assumes no prior experience with
Docker, Python or the command line.

**You may not need this.** The tool works with no setup at all at
<https://tbgh011.github.io/API-surface-mapper/>. Everything there runs in your
browser. Follow this guide only if you want the fuller results the server engine
produces: certificate transparency enumeration instead of a wordlist, responses
read directly instead of being blocked by CORS, and specification files parsed
rather than just linked.

On `stripe.com`, the difference looks like this:

| | documented | live hosts | to verify |
| --- | --- | --- | --- |
| Browser (the hosted page) | 1 | 7 | 84 |
| Server engine (this guide) | 2 | **28** | **0** |

Roughly fifteen minutes, most of it waiting for Docker to install.

---

## Before you start

- A Windows, macOS or Linux computer you can install software on
- A few gigabytes of free disk space. Docker Desktop itself is most of that;
  the server engine image is about 250 MB
- An internet connection

You do not need to know Python. You will type four commands in total, and this
guide gives you all four.

---

## Step 1: Install Docker Desktop

Docker is what runs the server engine. It packages everything the engine needs
so you do not have to install Python or any libraries yourself.

Download it from <https://www.docker.com/products/docker-desktop/> and run the
installer. Accept the defaults. On Windows it may ask to install or update WSL
and to restart your computer; let it.

**Then start Docker Desktop and leave it running.** This is the step people miss.
Installing Docker is not enough, it has to be running. You will know it is ready
when the whale icon appears in your system tray (Windows) or menu bar (macOS)
and stops animating. The first startup can take a minute or two.

---

## Step 2: Get the code

Go to <https://github.com/tbgh011/API-surface-mapper>.

Click the green **Code** button, then **Download ZIP**. Save it somewhere you
will find again, such as your Desktop or Documents folder, and unzip it. You
will get a folder named `API-surface-mapper-main`.

If you already use Git, this does the same thing:

```bash
git clone https://github.com/tbgh011/API-surface-mapper.git
```

Either way, remember where that folder is. You need it in the next step.

---

## Step 3: Open a terminal in that folder

The terminal needs to be pointed at the folder you just unzipped. Opening a
terminal anywhere else and typing the command will not work, which is the single
most common thing that goes wrong here.

**Windows 11:** open the folder in File Explorer, right-click any empty space
inside it, and choose **Open in Terminal**.

**Windows 10:** open the folder, hold <kbd>Shift</kbd>, right-click empty space,
and choose **Open PowerShell window here**.

**macOS:** open Terminal (press <kbd>Cmd</kbd>+<kbd>Space</kbd>, type
`Terminal`, press Enter). Type `cd ` — the three characters `c`, `d`, space —
then drag the folder from Finder into the Terminal window and press Enter. That
fills in the path for you.

**Linux:** most file managers have a right-click **Open in Terminal**. Otherwise
`cd` to the folder.

To check you are in the right place, type `ls` (macOS/Linux) or `dir`
(Windows) and press Enter. You should see `index.html`, `docker-compose.yml` and
a `server` folder listed. If you do not, you are in the wrong folder.

---

## Step 4: Start the server engine

Type this and press Enter:

```bash
docker compose up --build
```

**The first run takes one to three minutes** and prints a lot of text. It is
downloading a Python image and installing the engine's libraries. This happens
once. Later runs take a few seconds.

You will know it worked when the text stops scrolling and the last lines look
like this:

```
api-surface-mapper  | INFO:     serving the UI from /srv/static
api-surface-mapper  | INFO:     Started server process [1]
api-surface-mapper  | INFO:     Application startup complete.
api-surface-mapper  | INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

**Leave this window open.** Closing it stops the server. It will keep printing a
line for every request, which is normal and is how you can watch a scan work.

---

## Step 5: Open the tool

In your browser, go to:

```
http://localhost:8000
```

Use exactly that address. Do not open `index.html` by double-clicking it, and do
not use the GitHub Pages address, because neither of those will find the engine.

You should see the familiar page with one addition under the domain box: a green
**SERVER ENGINE** badge. That badge is your confirmation that everything is
connected. If it is missing, see Troubleshooting below.

---

## Step 6: Run your first scan

Type a domain you own or are authorised to test, and press **Map surface**.

A scan takes roughly twenty to sixty seconds depending on the size of the
domain. The status strip tells you which phase is running: the public directory,
then certificate transparency, then DNS resolution, then the spec probes, then
response headers.

What you should notice compared to the hosted page:

- Many more live hosts, because certificate transparency lists names that
  actually exist rather than names someone guessed
- The blue **to verify** count near zero, because the server can read the
  responses your browser could not
- Green rows carrying real detail, such as path and operation counts and any
  operations that declare no authentication

The [quickstart guide](https://tbgh011.github.io/API-surface-mapper/quickstart-guide.html)
explains how to read the results and what each colour means. It is also served by
the engine you just started, at <http://localhost:8000/quickstart-guide.html>.

---

## Stopping and starting again

To stop it, click the terminal window and press <kbd>Ctrl</kbd>+<kbd>C</kbd>.
Or, from that folder:

```bash
docker compose down
```

To start it again another day, open a terminal in the folder as in Step 3 and
run this. Note there is no `--build` this time, so it starts in seconds:

```bash
docker compose up
```

To update to a newer version later, download the repository again (or
`git pull`), then run `docker compose up --build` once to rebuild.

---

## Troubleshooting

| What you see | What it means | What to do |
| --- | --- | --- |
| `docker: command not found`, or `unrecognized command` | Docker is not installed, or the terminal was open before you installed it | Complete Step 1, then close and reopen the terminal |
| `Cannot connect to the Docker daemon`, or `the system cannot find the file specified` | Docker Desktop is installed but not running | Start Docker Desktop and wait for the whale icon to settle, then try again |
| Docker Desktop itself shows *"An unexpected error occurred"* mentioning a `.sock` file that *"cannot be accessed by the system"* | Leftover socket files from a previous crash, which Docker cannot delete or reuse | See "Docker Desktop will not start" below |
| `port is already allocated`, or `address already in use` | Something else on your machine is using port 8000 | See "Port 8000 is taken" below |
| `no configuration file provided` | The terminal is not in the project folder | Redo Step 3, and check with `ls` or `dir` |
| The page loads but there is no **SERVER ENGINE** badge | The browser is not talking to the engine | Confirm the address is exactly `http://localhost:8000`, and that the terminal from Step 4 is still open and running |
| The build seems frozen with no output | It is downloading, not stuck | Give it three minutes before worrying |
| *"Certificate transparency logs were unreachable"* in the results | The public CT service is down or rate limiting you | Nothing to fix. The scan falls back to the built-in wordlist and still works. Try again later |
| A scan on a large domain takes a long time | It is resolving hundreds of hostnames | Lower `MAX_HOSTS` in `docker-compose.yml`, for example to `100` |

### Docker Desktop will not start

If Docker Desktop crashes on startup complaining that a `.sock` file cannot be
accessed, it has been left holding orphaned socket files that Windows will not
let it delete. Restarting usually does not help, because each failed start
creates more of them.

The fix is to move the folders holding them aside, which Docker then recreates
cleanly. Quit Docker Desktop, then in PowerShell:

```powershell
Get-Process -Name "Docker Desktop","com.docker.backend" -ErrorAction SilentlyContinue | Stop-Process -Force
$stamp = Get-Date -Format yyyyMMdd-HHmmss
Rename-Item "$env:LOCALAPPDATA\Docker\run" "run.stale-$stamp" -ErrorAction SilentlyContinue
Rename-Item "$env:LOCALAPPDATA\docker-secrets-engine" "docker-secrets-engine.stale-$stamp" -ErrorAction SilentlyContinue
```

Start Docker Desktop again. You may need to repeat this once, because a crash
partway through startup can orphan a second set of files. The renamed
`*.stale-*` folders are inert and can be deleted after your next reboot.

### Port 8000 is taken

Open `docker-compose.yml` in any text editor and find this line:

```yaml
      - "127.0.0.1:8000:8000"
```

Change the **first** number only, for example to `8001`:

```yaml
      - "127.0.0.1:8001:8000"
```

Save, run `docker compose up` again, and use `http://localhost:8001`.

---

## A note on what you scan

Resolving a hostname and requesting a published document is ordinary,
unauthenticated traffic, and that is all this does. It reads what is public and
sends one GraphQL introspection query. It does not log in, guess passwords, or
attempt any exploit.

That said, it makes those requests from your own machine and your own IP
address, and it makes considerably more of them than the browser version.
Confirm you own the domain, or that it falls inside a bug bounty program or an
authorised engagement, before you scan it.

If you are running this somewhere other people can reach, set `SCOPE_ALLOWLIST`
in `docker-compose.yml` so the instance refuses anything outside the domains you
are cleared for. The [README](README.md#configuration) lists every setting.
