#!/usr/bin/env python3
# 1. **This formalizes a design document, not shipped code.** No claim here says anything about the actual Arkade compiler, emulator, or any deployed implementation. A gap between this formal model and running code is not covered and must not be implied to be covered.
# 2. **This is not a security audit and confers no security guarantee.** Passing model-checking or completing a proof means only that the *specific stated properties* hold under the *specific stated adversary model* — nothing broader. Do not use language like "PULSE is proven secure"; use "property P holds under assumptions A, checked/proved by method M."
# 3. **Trust-layer assumptions are modeled as assumptions, not derived.** The source document is explicit (§9, §9.1, §13.1) that TEE attestation, federation honesty thresholds, and enclave/committee trust are *not* cryptographically eliminated — they are the trilemma's third corner (§13.2). Model them as named axioms/oracles (e.g. `Assume: at least t of n enclaves are honest and attested`) and never attempt to prove them; flag prominently anywhere a proof's soundness rests on one.
# 4. **Every claim must be labeled** as one of: **proved** (machine-checked, unbounded), **model-checked** (bounded state space, e.g. TLC with a stated parameter bound — absence of a counterexample at that bound is not a proof for larger N), or **assumed** (an axiom taken from the source spec, not derived here). Do not let a model-checked or assumed claim read like a proved one anywhere in the output, including summaries and comments.
# 5. **Formalization requires resolving informalities the source document left as prose.** Every place you had to make a choice the `.md` did not pin down precisely (e.g., exact message formats in §7.5's exit notices, the wire serialization deferred to the ABI in §13.4, the exact adversary model for §9.4's capital sizing) must be listed explicitly in a "Formalization decisions" section, with the section number of the ambiguity and the choice made. Do not silently disambiguate.
# 6. **Do not present this as peer-reviewed or final.** It is a draft input to a whitepaper and is explicitly intended for a human researcher/editor to review, correct, and take ownership of before any publication or citation.
# 7. **No production or financial guidance.** Nothing in the formal artifacts should be read as advice to deploy, invest in, or rely on PULSE-secured funds; note this plainly if the work is shared outside the immediate research/editorial team.

"""Re-runs every model check and proof in this bundle and rejects unexpected results.

  python3 verify.py --tlc /path/to/tla2tools.jar --lean /path/to/lean [--mathlib DIR]

--mathlib is optional: without it the mathlib-dependent Pulse.lean is skipped and
only the dependency-free NonceSchedule.lean is checked. Negative cases must fail
for their NAMED property, never for a syntax or runtime error.
"""
import argparse, subprocess, sys, tempfile
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('--tlc', type=Path, required=True)
p.add_argument('--lean', type=Path, required=True)
p.add_argument('--mathlib', type=Path)
a = p.parse_args()
root = Path(__file__).resolve().parent
fail = []

OK = 'Model checking completed. No error has been found.'
CASES = {
    # positive: the protocol as specified in revision 2.2
    'Ceremony':              (0,  OK),
    'CeremonyFaults':        (0,  OK),
    'Exit':                  (0,  OK),
    'Nonce':                 (0,  OK),
    'ExitFiledNoticeFix':    (0,  OK),
    # negative: each removes one named defence and must lose its named property
    'CeremonyNoFinalityGate':(12, 'Invariant FinalitySound is violated.'),
    'CeremonyLastSealed':    (12, 'Invariant LastSealedSpendable is violated.'),
    'CeremonySealOnly':      (12, 'Invariant NoTheft is violated.'),
    'CeremonyBadOrder':      (12, 'Invariant LatticeBeforeTransition is violated.'),
    'ExitSealOnly':          (12, 'Invariant NoTheft is violated.'),
    'ExitUnboundedMining':   (12, 'Invariant NoSweepUnderExit is violated.'),
    'ExitUnsealedNotice':    (12, 'Invariant NoTheft is violated.'),
    'ExitNoFairness':        (13, 'Temporal property ExitOrPayout was violated.'),
    'NoncePerEpoch':         (12, 'Invariant NoKeyLeak is violated.'),
    'NonceCrash':            (12, 'Invariant NoKeyLeak is violated.'),
}

def module_of(cfg):
    for m in ('Ceremony', 'Exit', 'Nonce'):
        if cfg.startswith(m):
            return m
    raise SystemExit('no module for ' + cfg)

with tempfile.TemporaryDirectory(prefix='pulse-check-') as tmp:
    for cfg, (code, msg) in CASES.items():
        r = subprocess.run(
            ['java', '-cp', str(a.tlc.resolve()), 'tlc2.TLC', '-noGenerateSpecTE',
             '-workers', '1', '-metadir', str(Path(tmp) / cfg),
             '-config', str(root / (cfg + '.cfg')), str(root / (module_of(cfg) + '.tla'))],
            capture_output=True, text=True)
        out = r.stdout + r.stderr
        good = r.returncode == code and msg in out
        print(('  ok  ' if good else ' FAIL ') + cfg)
        if not good:
            fail.append(cfg + ' (rc=%s, wanted %s/%r)' % (r.returncode, code, msg))

r = subprocess.run([str(a.lean.resolve()), str(root / 'NonceSchedule.lean')],
                   capture_output=True, text=True)
out = r.stdout + r.stderr
good = r.returncode == 0 and 'sorry' not in out and out.count('does not depend on any axioms') == 4
print(('  ok  ' if good else ' FAIL ') + 'NonceSchedule.lean (4 theorems, no axioms)')
if not good:
    fail.append('NonceSchedule.lean: ' + out.strip()[:300])

if a.mathlib:
    r = subprocess.run(['lake', 'env', 'lean', str(root / 'Pulse.lean')],
                       cwd=a.mathlib, capture_output=True, text=True)
    out = r.stdout + r.stderr
    good = r.returncode == 0 and 'sorryAx' not in out and out.count("'Pulse.") == 6
    print(('  ok  ' if good else ' FAIL ') + 'Pulse.lean (6 declarations, no sorryAx)')
    if not good:
        fail.append('Pulse.lean: ' + out.strip()[:300])
else:
    print('  skip  Pulse.lean (no --mathlib given)')

print()
if fail:
    print('FAILED:'); [print('  - ' + f) for f in fail]; sys.exit(1)
print('All checks produced their expected result.')
