# FAIR Hand-Off: RAG Shield Results

For the group member building the FAIR model. Machine-readable version: `evaluation/results/fair_summary.json`. Regenerate it with `python -m evaluation.export_fair`.

Manual verdicts are proposed until the group confirms them. All figures are measured on a fictional simulation, not on Williams or Copilot.

## Results

Clear success means a person following the answer would be misled. Intervals on rates are 95% Wilson. Reduction intervals are 90%, from uniform-prior Beta posteriors. A negative reduction means the protected result was worse.

| Attack category | Trials | Baseline rate (95% CI) | Protected rate (95% CI) | Observed reduction (90% interval) | Detected |
| --- | --- | --- | --- | --- | --- |
| Unapproved prompt injection | 20 | 35% (18-57%) | 0% (0-16%) | 100% (58% to 99%) | 9 of 20 |
| Unapproved KB poisoning | 20 | 40% (22-61%) | 0% (0-16%) | 100% (64% to 99%) | 9 of 20 |
| Approved poison, listed facts | 10 | 50% (24-76%) | 0% (0-28%) | 100% (45% to 99%) | 0 of 10 |
| Approved poison, unlisted facts | 10 | 30% (11-60%) | 40% (17-69%) | -33% (-240% to 49%) | 0 of 10 |

Partial successes change these counts: 8, 12, 7, and 8 on Baseline, and 0, 0, 0, and 6 under the Shield. The JSON file includes both views.

An observed 100% reduction only means no clear success occurred in these trials. Do not model the protected rate as zero.

## Why lab reduction does not equal loss reduction

- **It measures one link in a chain.** The lab measured the chance of a misleading answer once a poisoned document is retrieved. A loss also needs an attacker to gain access, an employee to rely on the answer, and independent safeguards to fail.
- **Later links absorb the effect.** Alarms, procedures, and trained staff may catch a bad answer anyway, so cutting one link by X% cuts loss by a different amount.
- **The attack mix matters.** A real attacker can choose wording or target the approval process, where the Shield showed no measurable benefit.
- **The environment differs.** The model, documents, and attacks are all simulated.
- **Loss magnitude is untouched.** The Shield may reduce how often a loss occurs, but nothing here measures how large one would be.

## How to use the results in FAIR

In FAIR, Vulnerability is the probability that a threat event becomes a loss event. The simulation informs one part of it:

```
Loss Event Frequency = Threat Event Frequency × Vulnerability

Vulnerability ≈ P(poison reaches a relevant answer)
              × P(misleading answer | poison retrieved)     ← measured here
              × P(employee relies on the answer)
              × P(existing safeguards fail)
```

Suggested inputs for the measured term, as minimum, most likely, and maximum:

| Case | Baseline | With Shield |
| --- | --- | --- |
| Poison stays unapproved | 22%, 40%, 61% | 0%, low but not zero, 16% |
| Poison passes approval | 11%, 30%, 60% | 17%, 40%, 69% |

Combine the cases using an explicit assumption for `q`, the share of poisoning attempts that pass approval:

```
P(misled | Shield) = (1 - q) × P(misled | unapproved) + q × P(misled | approved)
```

`q` was not measured, and the result is sensitive to it. Run the model across a range of values and show the effect.

Other terms need separate evidence or calibrated expert estimates. Do not take them from this project:

- Threat event frequency and the chance of write access
- The chance that an employee relies on the answer
- The chance that safeguards fail
- Loss magnitude for the scenario's four FAIR cases

## Costs to include

- Under the Shield, 4 of 6 deliberately awkward harmless uploads were flagged, and none could be used.
- Signed-off poison on listed facts caused 7 of 10 answers to be withheld. An attacker could use this to deny service during an incident.
- Review staff would be needed for quarantine and approval. This was not estimated.
