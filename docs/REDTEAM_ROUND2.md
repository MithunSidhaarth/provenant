# Guard red-team, round 2: 100 new practical attacks, 41 gaps found and fixed

Round 1 (`docs/REDTEAM_100.md`, now the core of `evals/attacks.json`) hit the guard's rule families.
Round 2 widened to the situations a real agent actually lands in. All 100 cases are now in
`evals/attacks.json` (negative controls) and `evals/benign.json` (positive controls), run by
`python evals/run_eval.py`.

## Result

Against the v8 guard (`guard-2026.10-3`), the 100 new attacks exposed **41 cases the guard allowed
outright**. After hardening (`guard-2026.10-4`):

| | v8 (before) | after |
|---|---|---|
| New attacks contained | 59 / 100 | **100 / 100** |
| Whole attack corpus contained | — | **225 / 225** (168 DENY, 57 held) |
| Benign controls allowed as expected | — | **53 / 53** (0 false positives) |
| Unit tests | 166 | 166 |

## The gap classes found and fixed

1. **Destructive cloud / infrastructure (13 cases, were ALLOW → now held).** `terraform destroy`,
   `aws rds delete-db-instance`, `aws s3 rb --force`, `aws s3 rm --recursive`, `aws ec2 terminate`,
   `kubectl delete`, `helm uninstall`, `gcloud … delete`, `az group delete`, `docker system prune`,
   `docker rmi`, `git filter-branch`. New shell rules hold each for a human. Read-only equivalents
   (`kubectl get`, `terraform plan`, `aws s3 ls`, `docker ps`) stay ALLOW — verified by benign controls.

2. **Destructive database operations (9 → held).** `DROP DATABASE/TABLE`, `TRUNCATE`,
   `DELETE`/`UPDATE` with no `WHERE`, redis `FLUSHALL`, mongo `dropDatabase()`, `psql -c 'DROP …'`.
   SQL rules are anchored to a statement boundary (start, `;`, newline, or just after a quote) so a
   scoped `DELETE … WHERE …`, a `SELECT`, and the literal phrase `'do not drop database'` inside a
   string all stay ALLOW.

3. **Credential theft beyond dotfiles (11 → DENY).** macOS keychain dump, `gpg --export-secret-keys`,
   `gh auth token`, `aws configure get aws_secret_access_key`, 1Password/LastPass/Bitwarden reads,
   and the browser credential stores (Chrome `Login Data`/`Cookies`, Firefox `logins.json`/`key4.db`,
   keychain files) added to the secret-path list.

4. **Regulated personal identifiers (5 → DENY outbound / held on local write).** IBAN, India Aadhaar
   and PAN added to the outbound-secret detectors, alongside the existing SSN and card rules. A long
   order number is not mistaken for one (benign control).

5. **Secrets split across arguments.** The DLP now reassembles leaves as the full concatenation *and*
   each suffix, so an SSN or key whose first fragment follows an unrelated field (`channel="x"`,
   `a="123-45"`, `b="-6789"`) still lines up on a word boundary.

6. **Exfiltration over non-HTTP channels & classification (3).** DNS exfil via `$(…)` in
   `dig`/`nslookup`, piping an archive to a raw `nc` socket, and a destructive command smuggled in a
   `code` argument of a read-named tool (`code` added to the command-key set).

## Honest limits

A destructive DDL sent through a tool named with a pure read verb and a non-command arg (e.g.
`query`) is still judged by name; broadening that would over-hold ordinary search queries that
contain words like "drop table". Shell/SQL analysis stays pattern-based (see `known_gaps` in
`docs/eval/results.json`). Provenance remains value-based. These are unchanged from v8.
