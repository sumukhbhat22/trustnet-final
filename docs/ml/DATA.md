# Training data for the real-data model

**Dataset:** Risk-Based Authentication (RBA) login dataset, Wiefling et al. (public research dataset of login events).
**Licence:** check the licence on the dataset's download page before use and record it here: `LICENCE: ______ (confirmed by <name> on <date>)`. The code does not assume one.
**Never committed:** `data/` is git-ignored. Do not add the file to git.

## Download steps (you do this by hand)
1. Request or download the dataset from its official page (a request form may be required).
2. Put the CSV at `data/raw/rba-dataset.csv` (any name works).
3. From `backend/` run:
   `python -m ml.train_real --data ../data/raw/rba-dataset.csv --sample-frac 0.05`
4. Restart the API. `/api/health` then reports `model.source = "real"`.

If the model file is missing, the API trains the synthetic model and `/api/health` carries a `degraded_note`.

## Sampling
The file is read in chunks of 200,000 rows and sampled uniformly (default 5%, capped at 500,000 rows) so all time periods stay represented. Rows scanned, rows kept, sample fraction and whether the cap was hit are stored in the model metadata (`real_model.json`). Record the exact numbers from your run here: `SAMPLE: ______`.

## Feature mapping
The pipeline and agents still use the existing five-feature model. Only the training input changed.

| Model feature | From the dataset | Quality |
|---|---|---|
| login_hour | hour of Login Timestamp (UTC) | real |
| geo_distance | 50 if this user's country was seen earlier, else 100 | proxy, not a distance |
| session_duration | not available | constant 4.5 |
| data_volume | not available | constant 150 |
| api_calls | not available | constant 200 |

Not provided by the dataset and not used by this model: device-trust flag, MFA events, IP address, ASN, user agent (IP and user agent are dropped after loading; user id is salted-hashed with `TRUSTNET_DATA_SALT`).

## Split and labels
Time-based: the earliest 70% of rows (by timestamp) train, the latest 30% test. Rows with the account-takeover or attack-IP flag are excluded from training; the flags are used only to score the test period (ROC AUC, average precision). Test metrics are not computed if the test period holds only one class.

## What this does and does not show
Three of five features are constants, so the model effectively sees login hour and new-country. Results describe this one public dataset and say nothing about real-world accuracy. A rules baseline may do as well or better; Prompt 5 compares them.
