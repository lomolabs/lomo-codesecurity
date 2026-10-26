# Run the local service

From your reviewed backend checkout on Mac or Linux:

```sh
python3 scripts/start-lomo.py --check --json
python3 scripts/start-lomo.py
```

Windows uses the explicit native or Remote WSL launcher described in the extension README. Keep the backend checkout inside the selected WSL distro.

The check reports the first missing prerequisite and how to recheck. It uses a temporary, source-free Docker storage probe. On a fresh engine, normal startup may be needed to obtain that pinned build dependency first.

**Ready means:** the backend responds at your configured loopback origin. Scanner preparation comes later.
