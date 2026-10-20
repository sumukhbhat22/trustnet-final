# Evaluation

**Data statement.** Section B uses fictional generated users and attacks. It is not real-world accuracy. Section A uses a public dataset only if it was provided when this file was generated.

Seeds: [11, 12, 13, 14, 15] (mean ± population std). Held out: last 7 of 21 days; models trained on the first 14 days of normal behaviour.

## B. Synthetic comparison

| Variant | Precision | Recall | F1 | FPR | Mean min to first response | Alerts | Incidents | Campaigns detected |
|---|---|---|---|---|---|---|---|---|
| rules_only_baseline | 0.623 ± 0.039 | 0.487 ± 0.043 | 0.544 ± 0.022 | 0.046 ± 0.008 | 215.626 ± 197.166 | 34.200 ± 3.655 | 19.800 ± 2.400 | 9.0 / 16 |
| isolation_forest_alone | 0.655 ± 0.039 | 0.482 ± 0.048 | 0.555 ± 0.040 | 0.039 ± 0.003 | 99.278 ± 127.134 | 32.000 ± 1.673 | 18.200 ± 2.040 | 9.0 / 16 |
| full_pipeline | 0.737 ± 0.056 | 0.501 ± 0.042 | 0.596 ± 0.042 | 0.028 ± 0.005 | 99.668 ± 111.059 | 29.600 ± 1.357 | 16.000 ± 2.098 | 9.6 / 16 |
| ablation_no_correlation | 0.737 ± 0.056 | 0.501 ± 0.042 | 0.596 ± 0.042 | 0.028 ± 0.005 | 99.668 ± 111.059 | 29.600 ± 1.357 | 29.600 ± 1.357 | 9.6 / 16 |
| ablation_no_known_bad | 0.732 ± 0.054 | 0.487 ± 0.045 | 0.584 ± 0.040 | 0.028 ± 0.005 | 102.671 ± 128.730 | 29.000 ± 1.897 | 15.400 ± 2.417 | 9.0 / 16 |
| ablation_no_device_trust | 0.729 ± 0.057 | 0.468 ± 0.044 | 0.569 ± 0.042 | 0.027 ± 0.005 | 37.407 ± 66.456 | 28.000 ± 2.000 | 14.600 ± 1.960 | 8.4 / 16 |

Recall by scenario (mean over seeds):

| Variant | stolen_credentials | insider_exfiltration | slow_and_low | mimicry |
|---|---|---|---|---|
| rules_only_baseline | 1.00 | 1.00 | 0.08 | 0.02 |
| isolation_forest_alone | 1.00 | 1.00 | 0.06 | 0.02 |
| full_pipeline | 1.00 | 1.00 | 0.08 | 0.07 |
| ablation_no_correlation | 1.00 | 1.00 | 0.08 | 0.07 |
| ablation_no_known_bad | 1.00 | 1.00 | 0.08 | 0.02 |
| ablation_no_device_trust | 1.00 | 1.00 | 0.02 | 0.02 |

## A. Real data

Blocked: No dataset provided. Run: python evaluate.py --real-data ../data/raw/rba-dataset.csv

## Reading these numbers honestly

On F1 in this synthetic setup, the full pipeline scores higher (baseline 0.544, full pipeline 0.596, Isolation Forest alone 0.555). The generator was written by the project author, so the margin depends on how hard the scenarios were made. The fusion weights were fixed in advance and are not tuned.

Beyond raw accuracy the pipeline adds things this table does not score: plain-language reasons per score, correlation of repeated alerts into one incident (compare the Alerts and Incidents columns), bounded automatic response with human approval for irreversible actions, and an audit trail. If a baseline wins on F1, that is a fair result and is reported as such. Slow-and-low and mimicry rows show where every variant is weakest.

Mean time to first response is computed only over attack campaigns that were detected at all, so a variant that detects fewer campaigns can look faster; read it together with the Campaigns detected column.
