# External project testing

Tested on **19 October 2026**, with Node.js **22.23.2** and Semgrep **1.180.0**.
AgentO source revision: `ce00e71b88c6dc3809a3d4e96dc920df8f43c230`.

**The controlled tests pass. Source analysis of unfamiliar applications still has
substantial coverage gaps.** Six Express projects produced incomplete route or
handler extraction. None produced a grounded injection hypothesis or executable
injection plan. The Python control correctly selected black-box mode, and a
separate live test verified HTTP, browser sessions and three security rules.

The tested set includes a deployed application codebase, two security training
applications, a reference API, two application starters and a tutorial. These
results do not measure vulnerability precision or recall on production systems.

## Source results

Each repository was cloned from GitHub and checked at the exact revision in the
[case manifest](../scripts/evaluation/realworld-cases.json). Target dependencies,
package scripts and application modules were not executed during these checks.
No requests were sent to a public application or upstream demonstration server.

| Project | Extracted endpoints | Static candidates | Result |
| --- | ---: | ---: | --- |
| [OWASP NodeGoat](https://github.com/OWASP/NodeGoat/tree/c5cb68a7084e4ae7dcc60e6a98768720a81841e8) | 0 | 0 | Callback-based route registration was missed; adapter support check returned false. |
| [RealWorld Express API](https://github.com/gothinkster/node-express-realworld-example-app/tree/30b68e1e881462b2f4164ea09ab4c4f5699c7b0b) | 1 | 0 | Only `/` was extracted. Routes behind chained router exports were missed. |
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop/tree/399fba76194305a312693eee44f4df64bdf0c3ce) | 1 | 12 | Only `/metrics` was extracted. Training snippets produced 39 parse errors; the static scan was partial. |
| [NodeBB](https://github.com/NodeBB/NodeBB/tree/387099ddb7ddc55b27e7568395223f634279ab08) | 5 | 5 | Helper-based routes were missed. Three unresolved routes and seven unresolved handlers were reported. |
| [Express boilerplate](https://github.com/hagopj13/node-express-boilerplate/tree/179ae84efec61b14206d0305d941daed6c6d07f9) | 0 | 7 | Routes mounted through a route table and loops were missed; adapter support check returned false. |
| [Hackathon Starter](https://github.com/sahat/hackathon-starter/tree/d320edb22ea0c42d7cb17f3a7837f1ce5163e234) | 101 | 0 | Direct routes were extracted. Middleware and controller resolution produced 855 unresolved-handler records, plus conditional and unresolved-route warnings. |
| [Flask tutorial](https://github.com/pallets/flask/tree/d086db856be187255b8ec61ef409357393020f32/examples/tutorial) | 0 | Skipped | Correct black-box fallback. Python source analysis is unsupported. |

The [machine-readable results](evaluation/realworld/results.json) link all seven
complete observation files and their SHA-256 digests. They retain the discovery
mode, adapter support, extraction diagnostics, static scan status, source
references, model output, hypotheses and plans. Endpoint counts are extracted
declarations; they are not complete inventories of live routes.

Of 15 manually reviewed Express route references, five were extracted at the
correct mounted path. These references were selected during exploratory testing;
they are smoke checks, not a representative sample or whole-application recall
measure. All **24 static candidates were unbound to an endpoint**. They remain
source candidates, with no runtime confirmation. Zero findings is not a clean
security result for these applications.

All seven runs passed checks for unique evidence IDs, project bindings, existing
evidence references, hypothesis states and unchanged source checkouts. Some link
checks are vacuous where no endpoints or hypotheses were produced. No model
service was configured, and no credentials were read from AgentO's environment.
Cookie sensitivity, account ownership and authorization policies were not guessed
for the Express projects.

## Issues exposed

1. **Route registration needs broader syntax support.** NodeGoat passes the app
   into an exported registration function. NodeBB uses registration helpers.
   RealWorld exports chained `Router().use(...)` expressions. Express boilerplate
   mounts a table inside loops. Important routes disappear before planning.
2. **Source selection needs application boundaries.** Juice Shop stores incomplete
   code examples as `.ts` assets. Both source tools attempt to parse them, and the
   framework adapter refuses support for the repository as a whole. Its main
   server setup is also inside a function, leaving almost all routes unextracted.
3. **Controller and middleware resolution needs improvement.** Hackathon Starter
   demonstrates useful direct-route extraction, but unresolved global middleware
   is repeated across many endpoints. Its 855 records are diagnostic occurrences,
   not 855 independent defects or vulnerabilities.
4. **Static evidence loses its path to execution.** Juice Shop, NodeBB and the
   Express boilerplate contain 24 bundled-rule matches, but none map to extracted
   endpoints. No injection hypotheses or plans follow from those matches.
5. **Coverage must stay visible across stages.** Discovery selected `code-aware`
   mode for all six Express projects, although three failed the adapter support
   check. This reflects metadata selection, not successful extraction. The model
   also retained an empty diagnostic list despite framework warnings. Hosts must
   expose the separate source diagnostics and missing coverage.

The first repair priority is route topology and controller resolution, followed
by source-root/exclusion controls and endpoint association for static candidates.
This testing change does not modify those production components.

## Live Flask test

The [live result and retained evidence](evaluation/realworld/flask-live.json)
come from an unchanged copy of the cloned tutorial, Flask **3.1.2**, fresh SQLite
data and an ephemeral `127.0.0.1` listener. The host supplied a random session
secret, two temporary users and one known owner post. The server and temporary
data were removed after testing; the original checkout stayed clean.

| Check | Observed result |
| --- | --- |
| HTTP reads | `/` and `/auth/login` returned 200. Anonymous `/create` returned 302. |
| HTTP origin scope | A request to another loopback origin was rejected before access. |
| Browser navigation | Chromium loaded and inspected the login form. |
| Isolated authentication | Alice and Bob completed separate real HTML form logins and identity verification. |
| Owner edit route | Alice received 200 for `/1/update`; Bob received 403; anonymous access returned 302. No owner marker matched Bob's response. |
| Sensitive cookie | The authenticated `session` cookie had `HttpOnly`; values were redacted. |
| CORS | Responses did not grant access to the declared untrusted origin. |
| Independent rules | CWE-639, CWE-1004 and CWE-942 returned `REJECTED` for the selected observations. |

This test calls the existing browser/runtime APIs and CWE rules with explicit
target configuration and host-declared ownership. It does not run discovery-led
A01/A02/A05 orchestration, the verification judge, automatic planning or an LLM.
It establishes portability of these primitives, not full Flask support. Secure
cookies were not assessed because this local target used HTTP. Redirect-based
anonymous denial was recorded without converting it into a new authorization
verdict. No injection probes ran against Flask or the six Express applications.

## AgentO regression checks

All **24 package checks passed**, including typechecking and builds:
**1,242 tests passed**. The default runs skipped 104 opt-in tests. Separately,
**94 live tests passed** across 11 suites, including actual Semgrep, Chromium,
HTTP/HTTPS assessments, injection probes, evidence verification and fix replay.
These 94 tests cover the controlled local fixtures, not the seven cloned apps.

The remaining ten opt-in cases were not run: four native scanner integration
cases, three frontend integration cases, two live LLM browser cases and one
model-provider case. No paid model requests were made. The existing evaluation
helpers passed another nine tests, and the recorded benchmark passed offline
evidence and current-source verification; that benchmark was not rerun here.

See the [package results](evaluation/realworld/package-checks.json) and
[live suite results](evaluation/realworld/live-checks.json) for exact package
names and counts. Initial restricted runs failed on loopback listeners or child
process operations. Rerunning those affected tests with the required permissions
passed. Those initial environment errors are not counted as product failures.

## Repeat the external checks

Build the local packages in the [A05 setup order](../packages/a05/README.md#setup).
Install the pinned Semgrep tool and Chromium as documented in their packages.
Use fresh output paths. From the AgentO repository root, clone the pinned public
sources into a directory outside this checkout:

```sh
python3 - <<'PY'
import json, pathlib, subprocess
root = pathlib.Path('/tmp/agento-realworld-repeat')
root.mkdir()
cases = json.loads(pathlib.Path('scripts/evaluation/realworld-cases.json').read_text())['cases']
for case in cases:
    path = root / case['id']
    subprocess.run(['git', 'init', str(path)], check=True)
    subprocess.run(['git', '-C', str(path), 'remote', 'add', 'origin', case['repository']], check=True)
    subprocess.run(['git', '-C', str(path), 'fetch', '--depth', '1', 'origin', case['revision']], check=True)
    subprocess.run(['git', '-C', str(path), 'checkout', '--detach', 'FETCH_HEAD'], check=True)
PY

node scripts/evaluation/realworld.mjs \
  --repos /tmp/agento-realworld-repeat \
  --output /tmp/agento-realworld-source-results \
  --semgrep /tmp/agento-semgrep-venv/bin/semgrep
```

The runner refuses changed revisions, dirty checkouts and an existing output
directory. Each project gets a separate process with a 180-second deadline.
Exit code `0` means the recorded source checks completed without coverage gaps;
`2` means at least one case failed or had a gap. The recorded run returned `2`,
as expected from the observed limitations. A completed unsupported-stack control
means correct fallback, not a successful security assessment. Full observations
are saved before the runner moves to the next project.

To repeat the separate local Flask check:

```sh
python3 -m venv /tmp/agento-flask-repeat
/tmp/agento-flask-repeat/bin/python -m pip install 'Flask==3.1.2'
node scripts/evaluation/flask-live.mjs \
  --repo /tmp/agento-realworld-repeat/flask \
  --python /tmp/agento-flask-repeat/bin/python \
  --output /tmp/agento-flask-live-results.json
```

This command needs local listener and browser process permission. It returns
nonzero on a failed assertion, retains only normalized response metadata and
evidence, and cleans up its temporary server and data. Random credentials,
cookie values and the private owner marker are excluded from the result.

To check the recorded source artifacts offline:

```sh
python3 - <<'PY'
import hashlib, json, pathlib
root = pathlib.Path('docs/evaluation/realworld')
results = json.loads((root / 'results.json').read_text())
for case in results['cases']:
    artifact = root / case['artifact']
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() == case['artifactSha256']
    assert all(case['invariants'].values())
print('All seven artifact digests and recorded invariants match.')
PY
```

These digests detect artifact changes relative to the summary. They are not
signed attestations. The recorded runner and manifest hashes identify the
source-check procedure; a repeat run will have new timings and evidence IDs.
