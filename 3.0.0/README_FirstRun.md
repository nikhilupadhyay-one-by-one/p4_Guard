### If you are running for the first time - likely since you clone repo often - use these steps :

BRO, let's actually test Guard properly on your Windows laptop. 🔥

We'll do three things:

1. Verify the application launches.
2. Test whether it detects file modifications.
3. Test real-time monitoring and the dashboard.

We'll use a dummy folder first, not your actual personal files.

## **1. Extract and open the project**

Extract `p4_Guard_single_file.zip`.

Open the extracted `p4_Guard_single` folder. It should look something like this:

```
p4_Guard_single/
│
├── app.py
├── requirements.txt
├── requirements-dev.txt
├── README.md
├── REFACTOR_NOTES.md
│
├── tests/
│   └── test_app.py
│
└── .github/
```

Open PowerShell inside this folder.

## **2. Install dependencies**

First, check your Python version:

```
python --version
```

Guard requires Python 3.10 or newer.

Create a virtual environment:

```
python -m venv .venv
```

Activate it:

```
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, run this in the same window:

```
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Then activate again.

Install Guard's dependency:

```
python -m pip install -r requirements.txt
```

That's it. Guard uses SQLite, which is already included with Python.

## **3. Check whether Guard launches**

Run:

```
python app.py --version
```

Then:

```
python app.py --help
```



Expected

&#x20;You should see Guard's version and its available commands:



- `watch`
- `baseline`
- `audit`
- `history`
- `stats`

## **4. Test whether file modifications are detected**

This is the important part.

Create a dummy directory:

```
New-Item -ItemType Directory -Force .\guard-demo
```

Create a sample file:

```
Set-Content .\guard-demo\hello.txt "Original content"
```

Now tell Guard to fingerprint the folder:

```
python app.py baseline .\guard-demo -d .\guard-demo.db
```

You should see something similar to:

```
1 files fingerprinted
Baseline saved
```

Now check it:

```
python app.py audit .\guard-demo -d .\guard-demo.db
```

Expected result:

```
Clean. Nothing has changed since the baseline.
```

Now let's tamper with the file:

```
Set-Content .\guard-demo\hello.txt "Someone modified this file!"
```

Run the audit again:

```
python app.py audit .\guard-demo -d .\guard-demo.db
```

Expected detection

Guard should report something similar to:

```
~ changed   hello.txt

0 added, 1 changed, 0 removed.
```

The audit will return exit code `1` when it detects differences. That's intentional, not a crash.

**Congratulations, you've tested Guard's core integrity-checking functionality.**

## **5. Test real-time monitoring**

Now let's test the actual filesystem watcher.

Run:

```
python app.py watch .\guard-demo --dashboard --no-browser -d .\guard-demo.db
```

You should see something like:

```
Dashboard on http://127.0.0.1:8420

Watching ...\guard-demo
Tracking 1 files.
Press Ctrl+C to stop.
```

Open dashboard

Open Firefox and visit:

[Guard local dashboard](http://127.0.0.1:8420?utm_source=chatgpt.com)

[File Integrity Monitoring Dashboard](https://images.openai.com/static-rsc-4/jHiHXPd8wzwTjonuhElQs3ZI32ubwIFw9ADWbGcLonXQrgW8uwTULb831hOSbsmq82G7XwYokdp784w-Z2zYrWrMHbNjAZ37biB8aNFTYJLX5rKy44bwK2KBct2JdXDIM35kd2-wU9S7tMTxlIguRjAvZXh7gFdjXZMo5Mo4MzQ?purpose=inline)

[docs.stellarcyber.ai](https://docs.stellarcyber.ai/prod-docs/5.3.x/Using/Visualizer/Dashboard-FIM.htm?utm_source=chatgpt.com)

Now open a second PowerShell window in the project directory.

Create a new file:

```
Set-Content .\guard-demo\live-test.txt "Real time test"
```

Then modify it:

```
Set-Content .\guard-demo\live-test.txt "Modified in real time"
```

You should see events appearing in the original PowerShell window and the dashboard.

Stop monitoring with **Ctrl + C**.

## **6. Check event history and statistics**

After stopping the watcher:

```
python app.py history .\guard-demo -d .\guard-demo.db
```

And:

```
python app.py stats .\guard-demo -d .\guard-demo.db
```

These should show your recorded events and monitoring statistics.

## **7. Run automated tests**

Finally, let's test the code itself.

Install development dependencies:

```
python -m pip install -r requirements-dev.txt
```

Run:

```
python -m pytest -q
```

Then run the linter:

```
python -m ruff check app.py tests/test_app.py
```

**Your testing checklist**

0 of 10 completed

0%

Python version is 3.10 or newer

Dependencies installed successfully

Guard launches and displays version

Baseline creation works

Audit detects modified files

Live watcher detects new files

Dashboard displays events

History and statistics work

Pytest passes

Ruff reports no issues

**One thing I want you to do:** Start with steps 1–4 and show me the PowerShell output after the audit detects the modified file.

We'll verify the actual behaviour first, then move to real-time monitoring. I don't want to push an application to GitHub until we've confirmed it works on your machine. 😁