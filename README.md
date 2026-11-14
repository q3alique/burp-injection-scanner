# Burp Injection Scanner

An Intruder-style Burp Suite Pro extension focused on **injection detection** with built-in
response analysis and confidence scoring. Covers **SQLi, XSS, SSTI, RCE/cmdi, LDAP, XXE,
Path Traversal, NoSQLi, and CRLF** out of the box.

Built on the Montoya API (Burp Suite 2023.1+).

---

## Highlights

- **Visual insertion points** — select a value in the request editor and click *Add §§*, the
  same feel as Intruder markers.
- **Four attack modes** — Sniper, Battering Ram, Pitchfork, Cluster Bomb.
- **Nine payload classes** with curated built-in wordlists; bring your own per class.
- **Response analyser** — reflection context (html / attr / js), error-signature match,
  math-hit (SSTI `7*7→49`), sensitive-string hit (`/etc/passwd`, `win.ini`, `uid=`),
  auth-success hit (SQLi / NoSQLi login bypass), status-code flip, length delta, timing anomaly.
- **Weighted confidence score** per row (0–100 %) with a sortable live table.
- **Payload encoding wrappers** — URL, double URL, Base64 variants added per payload.
- **Context-aware payload pruning** — skip irrelevant classes per position (e.g. XSS on a
  numeric id).
- **Burp Collaborator OOB payloads** — enable a checkbox and RCE / XXE / SSTI / CRLF get
  extra OOB variants; interactions are summarised at the end of the scan.
- **Right-click** any result row → *Send to Repeater / Intruder / Comparer*.
- **Export tab** with six formats and file splitting:
  - **JSONL** (one row per line)
  - **JSON array**
  - **CSV**
  - **HTML report** (self-contained, styled)
  - **Markdown**
  - **SARIF 2.1.0**
- **DoS guardrails** — request budget preview with hard-cap confirmation, concurrency and
  per-request delay controls.

---

## Install

1. Download the latest `burp-injection-scanner-x.y.z.jar` from the
   [Releases](../../releases) page.
2. In Burp: *Extensions → Installed → Add → Extension type: Java → Select file*.
3. A new top-level tab **Injection Scanner** appears.

Requires Burp Suite **Professional** (Montoya API).

---

## Build from source

```
gradlew.bat shadowJar
```

Output: `build/libs/burp-injection-scanner-0.1.0.jar`.

---

## Usage

1. In Proxy / Repeater / Target, right-click a request → **Send to Injection Scanner**.
2. In the request editor (left pane), highlight the value you want to fuzz and click
   **Add §§**. Repeat for every insertion point.
3. In **Payloads** tick the classes you want (SQLi, XSS, …). Load a custom wordlist per
   class if desired.
4. In **Options** choose the attack mode, concurrency, delay, encoding wrappers, and whether
   to use context-aware pruning or Collaborator OOB.
5. Click **Start**. Results stream into the table, sorted by confidence descending.
6. Switch to **Export** to dump results as JSONL / JSON / CSV / HTML / Markdown / SARIF,
   optionally split by rows or size.

---

## Attack modes

| Mode          | Behaviour                                                      |
|---------------|----------------------------------------------------------------|
| Sniper        | one §§ at a time, every payload against each position          |
| Battering Ram | same payload into every position simultaneously                |
| Pitchfork     | one wordlist per position, consumed in parallel                |
| Cluster Bomb  | cartesian product of all positions × wordlists                 |

---

## Confidence scoring (summary)

Each response is scored 0.0–1.0 per payload class. Weights roughly:

- **SQLi** — error pattern (0.65), timing anomaly (0.45), auth-bypass with success keyword
  on an error→200 flip (0.80).
- **XSS** — active metachar survives reflection (0.55) + context bonus (html/attr/js).
  Error pages are penalised 0.4×.
- **SSTI** — `math_hit` (0.80), template error (0.30).
- **RCE** — sensitive string (0.70), timing anomaly (0.55).
- **LDAP / XXE / Path** — error / sensitive / length-delta combinations.
- **NoSQLi** — auth-success-on-flip (0.80), status change, length, timing.
- **CRLF** — header reflected (0.60).

Full logic: [`detect/Signal.kt`](src/main/kotlin/com/burpinj/detect/Signal.kt).

---

## Project layout

```
src/main/kotlin/com/burpinj/
├── InjectionScannerExtension.kt   # Montoya entry point
├── detect/     # Response analyser, scorer, signatures
├── engine/     # Scheduler, job runner, attack modes, replayer
├── payloads/   # Built-in payload sets per class
├── ui/         # Swing tabs: Request / Positions / Payloads / Options / Export + results
└── util/       # Helpers
```

---

## License

MIT. See [LICENSE](LICENSE).

> Use only on systems you are authorised to test.
