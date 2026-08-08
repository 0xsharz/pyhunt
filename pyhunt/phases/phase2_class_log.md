# Class group LOG — authorisation, IDOR, business logic

> Read `phase2_shared.md` first. This file adds the sinks, sanitisers,
> false-positive killers and PoC guidance for **your** class group only.

**Read this section before anything else in this file.**

Every other hunt group can be caught being wrong by a machine. If an INJ hunter
claims command injection and the payload never reaches a shell, the execution
gate says so in Python and nobody has to trust the hunter. **You do not have
that.** Your classes are in `UNDECIDABLE_BY_EXECUTION`
(`scripts/oracle/classes.py`), the gate returns `not_applicable` for them, and
nothing downstream will catch a mistake by running it.

That is not a defect in the run and you must never write it up as one.
Execution answers *"did this behaviour occur?"*. It cannot answer *"was this
behaviour allowed?"* — that needs the **intended policy**, which does not exist
in the runtime. A PoC can show user A reading user B's record, three times over,
in a clean container, and still not establish that doing so is wrong. The
missing premise is not obtainable by running more code.

Two consequences, and they run in opposite directions:

1. **Your findings are never "unproven".** They are `not_applicable`: outside
   what execution can decide. The report counts them in their own denominator so
   an honest reader can see that "18 of 25 proven" was really "18 of 19
   provable, plus 6 that no amount of execution could settle".
2. **Your evidence bar is higher than everyone else's**, because the only thing
   standing between your finding and the report is your own reasoning and Phase
   2c's adversarial re-read. §3 is that raised bar. It is not optional.

---

## 1. What you own, and the string you must emit

| `attack_class` routed here | `vuln_class` you must emit | CWE | Gate outcome |
|---|---|---|---|
| `auth_bypass` | `authorization` *or* `missing_auth` *or* `access_control` | CWE-862 / CWE-306 | `not_applicable` |
| `idor` | `idor` | CWE-639 | `not_applicable` |
| `access_control`, `authorization`, `missing_auth` | same string back | CWE-862 | `not_applicable` |
| `privilege_escalation` | `privilege_escalation` | CWE-269 | `not_applicable` |
| `business_logic`, `logic_error` | `business_logic` | CWE-840 | `not_applicable` |
| `mass_assignment` | `mass_assignment` | CWE-915 | `not_applicable` |
| `csrf` | `csrf` | CWE-352 | `not_applicable` |
| `rate_limit` | `rate_limit` | CWE-307 | `not_applicable` |
| `weak_crypto`, `cryptographic_failure` | `weak_crypto` | CWE-327 / CWE-330 | `not_applicable` |
| `hardcoded_secret` | `hardcoded_secret` | CWE-798 | `not_applicable` |
| `information_disclosure` | `information_disclosure` | CWE-200 | `not_applicable` |
| `insecure_design`, `security_misconfiguration` | `insecure_design` | CWE-1188 / CWE-16 | `not_applicable` |
| `race_condition` | `race_condition` | CWE-362 / CWE-367 | `no_event` — see §2 |
| `regex_dos` | `regex_dos` | CWE-1333 | `no_event` |
| `integer_overflow` | `integer_overflow` | CWE-190 | `no_event` |

**The exact `vuln_class` string is load-bearing.** The gate matches it against
`UNDECIDABLE_BY_EXECUTION` by substring, and two of the routing labels above —
**`auth_bypass` and `logic_error`** — are **not** in that table. Emit those
strings and your finding is recorded `no_event`, which reads to anyone scanning
the report as *"we ran it and nothing happened"*. That is the opposite of the
truth. Emit `authorization` (or `missing_auth`, or `access_control`) and
`business_logic` instead. Check any string you are unsure of:

```bash
"${SKILL_DIR}/.venv/bin/python" -c \
  "import sys; sys.path.insert(0,'${SKILL_DIR}/scripts'); \
   from oracle.classes import is_undecidable; print(is_undecidable('business_logic'))"
```

A non-`None` answer means the gate will record `not_applicable`. `None` means it
will not.

---

## 2. Undecidable is not the same as unobserved

Three of your classes — `race_condition`, `regex_dos`, `integer_overflow` — are
*in principle* decidable by running code. A race really can be demonstrated; a
catastrophic regex really does hang. They are in your group because they are
logic reasoning, not because execution is powerless.

What they lack is an **instrument**. The audit hook watches process spawn, file
open, socket connect, exec/compile, pickle and marshal. None of those fires when
two threads interleave badly or a regex backtracks for nine seconds. So the gate
will record `no_event`, and for these three that is the honest label: *the
observer saw nothing, which is not a refutation.*

Do not paper over the difference. For an undecidable class, say in `poc.notes`
that execution cannot settle it. For these three, say what you actually
measured — the interleaving you produced, the wall-clock curve, the overflowed
value — and note that the observer has no event for it.

---

## 3. The evidence bar that replaces the oracle

Every LOG finding must carry all seven. A finding missing any of them is not
ready; go and get the missing piece rather than shipping a guess.

1. **Name the intended policy, and cite where it is stated.** A sibling handler
   that *does* check, a permission class, a docstring, a test, a migration, a
   README line, a comment. "There is no owner check" is only a finding once you
   can say what the owner check should have been and why you believe that.
2. **Show the asymmetry.** The single strongest evidence in this class is a
   pair: endpoint A checks, endpoint B does not, and both reach the same object.
   Quote both, with `file:line`. Asymmetry is evidence about *intent* — which is
   exactly the premise execution cannot supply.
3. **Name both principals concretely.** Who the attacker is (anonymous,
   any authenticated user, a tenant, a low-privilege role) and whose data or
   capability they obtain. "A user could access another user's data" names
   neither.
4. **Quote the handler in full, not a slice.** Your claim is that a check is
   *absent*. A 6-line excerpt can hide the check on line 7, and a reviewer
   cannot see what you cropped out. Show the whole function, the decorators
   above it, and the route registration.
5. **Exhaust the indirect controls before claiming absence.** Grep and read:
   decorators on the view and on its base class; middleware in the app factory /
   `MIDDLEWARE` / `add_middleware`; `dispatch()` and `get_permissions()` and
   `get_queryset()` overrides; a `before_request` hook; a router-level
   dependency (`Depends`); a database row-level policy. An authorisation check
   three frames up is still an authorisation check, and missing it is the most
   common false positive in this group.
   If a control exists but is **ineffective**, that is a different, better
   finding — say why it is ineffective at this specific object.
6. **State the blast radius.** Which records, whose, how many, and whether the
   operation reads or writes. "Cross-tenant read of every invoice" and "read of
   one field on your own record" are not the same finding.
7. **Pre-empt the strongest counter-argument.** Write down the best case *against*
   your finding and answer it. Phase 2c re-reads your work on a different model
   with the explicit job of disproving it; the counter-argument you did not
   consider is the one that kills the finding, and if it is fatal you would
   rather know now.

`hedged_language: true` on a LOG finding is a message to yourself that step 1 or
step 5 is not finished. Go finish it.

**Do not use `design_controls` to clear anything here.** A listed auth
middleware is a pointer to read, never proof the path is guarded — the whole
class of bug you are hunting is "the control exists and does not cover this
case".

---

## 4. Authorisation, IDOR, privilege escalation

**Authentication is not authorisation.** `@login_required`,
`IsAuthenticated`, a valid JWT, an API-gateway assertion and a `/protected/`
path prefix all prove the caller is *a* valid user. None proves they own *this*
object.

Python shapes that are IDOR (CWE-639) unless a check is present elsewhere:

```python
# Django
obj = get_object_or_404(Order, pk=pk)                       # IDOR
obj = get_object_or_404(Order, pk=pk, user=request.user)    # fine

# SQLAlchemy / Flask
obj = Order.query.get(pk)                                   # IDOR
obj = Order.query.filter_by(id=pk, owner_id=current_user.id).first_or_404()

# Django REST Framework
def get_object(self):
    return Order.objects.get(pk=self.kwargs["pk"])          # IDOR — see below
```

That last one is worth its own note because it is a real, repeated bug: DRF's
generic `get_object()` calls `self.check_object_permissions(request, obj)`. A
hand-written `get_object()` that forgets that call **silently skips every
`has_object_permission`** you wrote, and the permission class still appears in
`permission_classes`, so the code reads as protected. Grep every custom
`get_object` in the repo.

Other high-yield shapes:

- **Object ID in a body field** rather than the path — `{"account_id": 7}` —
  where the handler trusts it instead of deriving it from the session.
- **Multiple IDs on one endpoint.** Evaluate each independently; each unchecked
  one is a separate finding.
- **Role read from the request** (a header, a claim the service issues to
  itself, a `role` form field) rather than from server state.
- **A tenant/org scope taken from input** instead of from the session.
- **Confused deputy**: the handler forwards the user's ID downstream using a
  *service* credential, so the downstream cannot enforce per-user rules and the
  caller cannot either. Whoever holds the service credential must do the check;
  if nobody does, that is the finding.
- **Privilege escalation**: any path where a lower role reaches an operation
  reserved for a higher one — a shared helper called from both an admin view and
  a user view, a `is_staff` check on the list endpoint and none on the detail
  endpoint, a management command exposed over HTTP.

**Format validation does not authorise.** A UUID regex, a Pydantic `int`, a
range check — all confirm the ID is well-formed and nothing about who owns it.

---

## 5. Mass assignment, CSRF, rate limiting

**Mass assignment (CWE-915).** The question is which fields the caller may set,
not which endpoint they may call. Endpoint-level role gates do not satisfy it —
permission to *use* an endpoint is not permission to modify *every field it
accepts*.

- Django `ModelForm` / `ModelSerializer` with `fields = "__all__"` and no
  `read_only_fields`; DRF `serializer.save(**request.data)`.
- A FastAPI/Pydantic request model that includes `is_admin`, `role`, `balance`,
  `status`, `owner_id`, `price`, `created_at`.
- `Model.objects.update(**request.POST.dict())`, `setattr` loops over
  `request.json`, `obj.__dict__.update(payload)`.
- The cross-endpoint test: a sensitive field that is explicitly stripped or
  overridden in a **higher-trust** endpoint but not in a **lower-trust** one is
  the asymmetry from §3.2, handed to you.

Schema validation (Pydantic, JSON Schema, DRF field types) validates **shape and
format, never authorisation**. Do not accept it as the control.

**CSRF (CWE-352).** Django's `CsrfViewMiddleware` is on by default — so grep
`@csrf_exempt` and `csrf_exempt(` and read every hit, and check the middleware
is actually in `MIDDLEWARE`. Flask needs `CSRFProtect` explicitly. DRF's
`SessionAuthentication` enforces CSRF; `TokenAuthentication` does not need it
(the credential is not ambiently sent). A state-changing `GET` is CSRF by
construction. `SameSite=Lax` cookies mitigate the common case and do not cover
top-level `POST` from a subdomain — say what you found rather than assuming.

**Rate limiting (CWE-307).** The bug is almost never the absence of a limiter;
it is the **key**. A counter bound to something the attacker can rotate — a
fresh session, an ephemeral cookie, a client-supplied header, a spoofable
`X-Forwarded-For` when the app is not behind a proxy that overwrites it — is
bypassable however atomic it is. On an **unauthenticated** endpoint that gates
credentials, that is an authentication bypass, and severity follows what the
limit protects (login attempts → account takeover).

---

## 6. Crypto, secrets, disclosure, configuration

**Weak crypto (CWE-327 / CWE-330).** Attacker-controlled input is **not**
required — the flaw is in the protection mechanism itself, so do not dismiss
these for lack of a tainted source. What to flag, in a security-sensitive
context (auth, sessions, signatures, tokens, PII):

- `hashlib.md5` / `sha1` for integrity, signatures or passwords; any bare hash
  for a password where `bcrypt`/`scrypt`/`argon2`/`pbkdf2_hmac` belongs;
- `random`, `random.randint`, `uuid.uuid1`, `time.time()` used to mint tokens,
  session IDs, password-reset links or nonces — `secrets` is the correct module;
- `AES.MODE_ECB`, a hard-coded or reused IV, a static salt, RSA < 2048;
- `==` comparing a secret, a token or an HMAC — `hmac.compare_digest` exists
  because the timing difference is exploitable;
- TLS verification disabled: `verify=False` (requests), `ssl._create_unverified_context`,
  `check_hostname=False`, `CERT_NONE` (CWE-295).

**Hardcoded secrets (CWE-798).** A literal key, token, password or private key
in source, in a default argument, in a settings module, or in a fixture that a
production path can read. `SECRET_KEY = "dev"` matters precisely because it
signs the session cookie. Check whether an env-var lookup **falls back** to the
literal — `os.environ.get("SECRET_KEY", "dev")` is the same bug with a coat on.

**Information disclosure (CWE-200).** Be strict here, because the class attracts
noise. A broad `except` (or `except Exception`) that prints, logs, returns or
formats the caught exception, a traceback (`traceback.format_exc()`,
`print_exc()`) or an object's `repr` can leak secrets that object carries:
request and connection objects embed headers including `Authorization`, URLs
embed credentials, config objects embed keys. **Report it only when a
secret-bearing value is provably in scope of the printed expression** — e.g. an
HTTP request built with a token header, reachable from that `except` block. A
bare `traceback.format_exc()` with no secret in scope is **not** a finding. Also
in this class: `DEBUG = True` reachable in production, a stack-trace error page,
and PII written to logs.

**Insecure design / misconfiguration.** A missing control rather than a broken
one: no authorisation layer at all on an internal API, permissive CORS
(`allow_origins=["*"]` with `allow_credentials=True` — which browsers reject, so
check what the code actually sends), `ALLOWED_HOSTS = ["*"]`, a debug route left
mounted, an admin interface on the same port with no separate auth. Emit
`vuln_class: "insecure_design"` — `security_misconfiguration` is not in the
undecidable table and would be recorded `no_event`.

---

## 7. Race conditions, ReDoS, integer overflow

These three are yours, and §2 explains why their gate outcome differs.

**Race / TOCTOU (CWE-362, CWE-367).** Four shapes:

- *check-then-act* — a permission, balance or state check, then a separate action
  that assumes the check still holds;
- *read-modify-write* — read a value, compute, write back with no atomic update.
  In Django the fixes are `F()` expressions and `select_for_update()`; their
  absence around a counter, a balance or a quota is the finding;
- *fire-and-forget async* — a security-critical operation dispatched to
  `ThreadPoolExecutor`, `asyncio.create_task`, Celery or a bare un-awaited
  coroutine, with the response sent before it completes;
- *TOCTOU across API or filesystem boundaries* — `os.path.exists` then `open`,
  `stat` then use, on a shared or world-writable path.

For each: what state does the async or unlocked operation mutate, does a later
operation depend on that mutation, and is there a lock, a transaction or a
constraint that guarantees ordering? If not, name the invariant that breaks —
double-spend, duplicate provisioning, a count limit exceeded, an orphaned
record.

**ReDoS (CWE-1333).** Python's `re` has no backtracking limit, so a nested
quantifier or overlapping alternation (`(a+)+$`, `(\s*\w+)*`) matched against
attacker-length input hangs the worker. Measure it: show the wall-clock curve
across input lengths in `run_output`. `re.fullmatch` does not help; a length cap
applied *before* the match does.

**Integer overflow (CWE-190).** Python ints do not overflow, so this is almost
always about a value crossing into something that does — `struct.pack`, a C
extension, a database column, a `ctypes` call — or about a *sign*/*bounds*
mistake used as an index, a size, a price or a loop bound. Say which.

---

## 8. False positives this group produces, and how to avoid them

- **Missing the check three frames up.** §3.5. This is the big one; do the greps
  before you write.
- **Calling a design decision a vulnerability.** A public read endpoint for
  public data is not IDOR. Ask: does this let the caller obtain data or
  capability they could not otherwise obtain? If not, it is at most
  `informational`.
- **Reporting the framework default as the bug.** Django's CSRF middleware is on
  unless removed; DRF's generic views do call `check_object_permissions`. Confirm
  the deviation, do not assume it.
- **Speculating about infrastructure.** An API gateway, a WAF, a service mesh
  policy or a network ACL you cannot read does not exist for your purposes — and
  equally, do not *invent* one to excuse a missing check.
- **Bulk-eliminating from one caller.** A helper called from an admin view and a
  user view is reachable by the user.
- **Stacking severity on a chain you did not show.** If the impact needs a second
  bug, say so and file the chain as a `gaps_observed` note.

---

## 9. What to run, and what to write in `poc.notes`

You may still execute — and often should, because a demonstration makes the
finding concrete for a human reader even though it settles nothing formally.
In Proof mode, drive the target's own entry point as each principal and record
what came back.

Then write **one line** in `poc.notes` with three parts: what you executed, what
it showed, and the specific policy question execution cannot answer.

> `ran get_order(2) authenticated as user 1; returned user 2's order rows;
> whether cross-tenant reads are intended is not decidable from the runtime —
> orders/views.py:41 fetches by pk with no owner filter, while
> orders/views.py:88 filters by request.user`

Set `needs_poc: false` — execution was available and you used it; the limit is
the class, not the environment. Expect the gate to record `not_applicable`.

If execution is unavailable (Static mode), omit the `poc` object, set
`needs_poc: true`, and put the same three-part sentence in the description.

**Never drop such a finding for want of executed proof, and never dress it up as
proven either.** Both failures are worse than the honest label the gate already
has for it.

---

## 10. Do not eliminate these

- **A missing authorisation check because "the UI never sends that value".** The
  client is not a control.
- **An IDOR because the identifier is a UUID.** Unguessable is not authorised;
  identifiers leak through logs, referrers, exports and other endpoints. It
  lowers severity by one tier at most, and only if you say so explicitly.
- **A business-logic invariant violation because the attacker only harms
  themselves.** Duplicate provisioning, double-spend, exceeding a count limit
  and minting duplicate active credentials are **new capabilities** even on the
  attacker's own account — a count-controlled resource has value precisely
  because the count is controlled.
- **Weak crypto because no tainted source reaches it.** The flaw is the
  mechanism (§6).
- **A finding because you could not write a PoC for it.** That is this whole
  file.

**Severity floors.** Cross-tenant read or write of another principal's data:
`high`. Full authentication bypass, or privilege escalation to an
administrative capability: `critical`. A hardcoded credential that is live in a
production path: `critical`. Do not downgrade any of these for the absence of an
executed proof — the gate has already recorded, in its own field, that execution
was never the right instrument.
