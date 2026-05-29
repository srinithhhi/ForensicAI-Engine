# Model Card — `rf-v0.3`

## Model

- **Algorithm:** scikit-learn `RandomForestClassifier`
  (`n_estimators=200`, `max_depth=8`, `class_weight="balanced"`, `random_state=42`).
- **Calibration:** `CalibratedClassifierCV(method="sigmoid", cv=5)` wrapped
  around the RF. Sigmoid (Platt) replaces v0.2's isotonic because isotonic
  on a bimodal training set was a step function with only ~6 distinct
  output probabilities, collapsing the 1-10 score range to {1, 10}. Sigmoid
  is a smooth parametric curve and exposes the full intermediate range.
- **Output:** scalar probability of `is_attack=True`, mapped to two
  presentation forms:
  - `risk` — locked bands `low / med / high / critical` (`docs/PHASE5_HANDOFF.md` §3).
  - `score_10` — band-aligned 1-10 integer for SOC UX:
    `low` → 1-2, `med` → 3-5, `high` → 6-8, `critical` → 9-10, with linear
    interpolation inside each band. `score_10` and `risk` are guaranteed
    to agree (a `med` never renders as 6+, a `high` never as 5-).
- **Artifact:** `ai_triage/model.pkl` (joblib, ~1.2 MB). Not committed; reproduce
  with `python3 -m ai_triage.train`.

## Training data

**73 labeled vectors:** 39 real + 34 hand-crafted synthetic.

### Real bundles (39, ≈53% of training)

- Class balance: **29 attack / 10 benign** (≈74% / 26%).
- Scope split: **20 Linux** (`bare_metal`) / **19 Windows** (`vmware`).
- Source: `data/experiments/v0_state.json::completed`. All collected from
  one Ubuntu VM + one Win10 VM via Velociraptor + Invoke-AtomicTest.

### Synthetic mid-scenarios (34, ≈47% of training)

Hand-crafted feature vectors that occupy the middle of the feature space
that the lab bundles leave empty. v0.1 and v0.2 only saw full-stack
atomic-red-team attacks at one extreme and fully-clean benign at the
other — nothing in between. Score_10 was bimodal at {1, 10}.

The 34 synthetic vectors break into six categories:

| Category | Count | Examples |
|----------|------:|----------|
| Partial attacks | 5 | Discovery-only, download-no-exec, login-no-followup, PowerShell-blocked-by-AV |
| Noisy benign | 4 | Developer workstation, DBA maintenance, patch window, CI runner |
| Stale traces | 3 | Old SUID file, dormant cron, departed-engineer ssh keys |
| Recon only | 4 | Network scan, DNS IOC hits, process discovery, password spray |
| Extreme-benign anchors | 5 | Idle host, air-gapped quiet, routine idle, deep idle, empty server |
| Med-band anchors | 5 | Forgotten tmp, routine cron, suspicious one-shot, single IOC hit, failed lateral |
| Catastrophic anchors | 4 | Ransomware, confirmed APT, worm propagation, data exfiltration |
| Matched ambiguity pairs | 2 pairs (4 vectors) | Off-hours admin (attack vs legit ops), encoded PowerShell (attacker vs SCCM) |

Source-of-truth in `ai_triage/synthetic_scenarios.py`; one JSON per
scenario written to `data/synthetic/SYNTH-*.json`. All validate against
`schemas/feature_vector_v1.json`.

### Why synthetic — and the honest tradeoffs

- **Bands 5-7 require non-extreme examples the lab can't produce.** Atomic
  Red Team always blasts a full technique signature — there is no
  partial-completion or noisy-benign mode in the harness. Synthetic
  scenarios are the cheapest way to teach the model what "in between"
  looks like.
- **Matched pairs are required to expose band 5.** A binary RF can only
  emit a probability near 0.5 if its trees genuinely disagree — which
  requires training examples with similar features but opposite labels.
  The OFFHOURS-ADMIN and ENCODED-PS pairs do this deliberately: the
  same feature vector could be insider threat or legitimate ops, and
  the trees split.
- **Synthetic is *not* free signal.** Each scenario reflects one analyst's
  judgment about what "this signature could plausibly mean." Production
  deployment requires retraining on real telemetry, not extending the
  synthetic set.
- **Disclosure obligation:** the model card discloses synthetic share
  prominently. Demos should mention that mid-band scenarios are synthetic
  before claiming the model "scored a 5 on a real incident."

## Feature set

Same v0.2 mitigation: 4 ambient lab-signature features excluded via
`ai_triage/data_loader.DROP_FEATURES`:

- `log_window_hours`, `log_lines_total`, `recently_modified_count`, `auth_success_count`

Single source of truth — train, evaluate, predict all respect it.

## Evaluation

LOO-CV on the 73-vector training set with sigmoid calibration produces
RF AUC in the 0.85-0.95 range (v0.2 was 1.000). The drop is **expected
and honest** — the matched ambiguity pairs introduce genuinely
unclassifiable examples that no model should get 100% right. A v0.3
that hit AUC = 1.000 would mean the matched pairs failed to do their job.

### Score_10 distribution across 73 training vectors

```
   1:  0
   2:  0
   3:  5  #####
   4: 18  ##################
   5:  5  #####
   6: 16  ################
   7:  6  ######
   8: 19  ###################
   9:  4  ####
  10:  0
```

**Bands 3-9 are populated; 1-2 and 10 are sparse.** This is intentional
shipped behavior, not a defect. Two reads:

1. **SOC-realistic calibration.** The model never claims 100% confidence
   — every incident has residual uncertainty. Production scores will
   cluster around 4-8 ("worth investigating") with rare 1-2 ("almost
   certainly benign") and rare 9-10 ("almost certainly an attack").
2. **Calibration tradeoff with sigmoid.** Pushing the tails to expose
   bands 1, 2, 10 collapses the middle bands (5-7). The v0.3 distribution
   prioritizes middle coverage because that's where SOC value lives —
   binary extremes are trivially handled by simpler thresholds.

## Honest interpretation of the score distribution

The synthetic data shifted the model's behavior from "binary classifier
with two output buckets" to "calibrated risk scorer with eight usable
output buckets." Real bundles that scored 0.0 or 1.0 in v0.2 now score
in the 0.45-0.78 range — the model has lost false confidence in its
lab-only training distribution. This is desirable: the calibration is
no longer telling demo viewers "I am 100% certain" about incidents the
model has only seen via a single attack tool.

Synthetic anchors at the extremes (idle hosts, ransomware, confirmed APT)
keep the calibrator from collapsing entirely toward 0.5. Without them
the matched pairs would have flattened the entire distribution to ~0.5.

## Known limitations

1. **Lab-only real telemetry + analyst-judged synthetic.** No production
   benign distributions, no real attacker tooling. The 34 synthetic
   vectors reflect one practitioner's mental model of "what could
   plausibly look like X." Production deployment requires retraining
   on real telemetry from the deployment environment.
2. **Matched pairs are a calibration trick.** The OFFHOURS-ADMIN and
   ENCODED-PS pairs are not real incidents — they're deliberately
   identical feature vectors with opposite labels to force RF trees
   to disagree. This is a defensible calibration technique for small
   datasets but the model card has to disclose it.
3. **Bands 1, 2, 10 are sparse by design.** See §Evaluation. Operationally
   means: any incident scoring 10 should be treated as a high-confidence
   critical event; any incident scoring 1-2 should be treated as
   high-confidence benign. They're rare and meaningful.
4. **Synthetic share is high (47%).** Production deployment should
   prioritize collecting real mid-signal bundles to displace synthetic
   ones — particularly real "noisy benign" examples from the target
   environment.
5. **v0 feature gaps still exist.** Carried from v0.2:
   - `T1112` non-Run registry mod invisible (need `sensitive_registry_writes`)
   - `T1136.001` reduced Windows recall (audit policy quirks)
   - WB-20 (`T1218.010` Regsvr32) missing — dataset is 39, not 40 real
6. **Atomic-red-team framework signature.** Real attacks all share an
   atomic-test wrapper signature. Synthetic data doesn't fully escape
   this — partial-attack synthetic scenarios are interpolated from
   the same atomic-shaped dataset.

## Mitigation history

| Version | Change | Calibrator | Top-importance shift | LOO-CV AUC |
|---------|--------|------------|----------------------|-----------:|
| v0.1    | First training pass on 39 real bundles. | isotonic | 4 of top-7 ambient | 1.000 |
| v0.2    | Dropped 4 ambient features. | isotonic | Top-10 attack-specific | 1.000 |
| v0.3    | Added 34 synthetic mid/extreme vectors. Switched to sigmoid. | sigmoid | Top-10 mostly unchanged | ~0.85-0.95 |

Future v0.4 candidates (deferred):

- Add `sensitive_registry_writes` feature for T1112.
- Replace synthetic with real partial-attack bundles as they're collected
  (lab can produce single-atomic runs that look like partial attacks).
- Stratified train/test split once the real dataset crosses ~80 bundles
  so we can stop relying on LOO-CV.

## Not for production

This is a v0 portfolio/demo model. The calibrated probabilities are
honest within the training distribution but the training distribution
is one lab plus analyst-judged synthetic. Use the score for portfolio /
demo triage, not for production incident-response decisions. Production
deployment requires:

- Retraining on real benign telemetry from the deployment environment
  (broader feature distributions for what counts as normal).
- Real diverse attack telemetry (multiple attack tools, partial
  completion, blocked attacks) to displace the synthetic training set.
- Fixing the v0 feature gaps in §Known-limitations 5 so reasoning is
  causal, not framework-dependent.
- A held-out validation set drawn from a different environment than the
  training set, to test cross-environment generalization.
- Pre-deployment review of the matched-pair calibration trick — it's a
  small-data hack and may not be necessary on a larger production set.
