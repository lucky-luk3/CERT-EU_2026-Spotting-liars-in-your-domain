# Rust in the Boiler — Spotting the Liars in Your Domain

**Four layers to find the Active Directory permissions whose name says one thing and whose privileges say another — classical analysis plus local AI, and nothing leaves your machine.**

Demo material from the talk *"Rust in the Boiler: Spotting the Liars in Your Domain"*, presented by **Luis F. Monge** at the **CERT-EU Annual Conference 2026**.

[![License: CC BY 4.0](https://img.shields.io/badge/License-CC_BY_4.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![GrexID](https://img.shields.io/badge/by-GrexID-0b3d91.svg)](https://grexid.eu)

---

## What this is

Every Active Directory accumulates *rust*: groups and accounts whose privileges have drifted far away from what their name, description or OU suggests. `MARKETING-USERS` with a path to Domain Admins. A "temporary" helpdesk group that can reset tier-0 passwords. Nobody put them there on purpose, and nobody is looking for them — except the intruder.

This project takes the SharpHound/BloodHound collection you already have and runs it through four layers, each one narrowing the list and explaining why:

| Layer | Name | What it does | Technique |
|---|---|---|---|
| 1 | **Steel · Risk scoring** | One explainable number per object: what it controls, who controls it, distance to Domain Admins, how many attack paths run through it | Deterministic, weighted features from the BloodHound graph |
| 2 | **Steel · Graph analysis** | The shape of the domain — interactive scatter of any two metrics, plus "where does this object get its rights from?" (explicit ACE vs inherited from a forgotten OU) | Plotly, raw SharpHound JSON |
| 3 | **Steam · Anomaly consensus** | Which groups look *unlike* the rest, independently of their score — with the reason each was flagged | Isolation Forest + Local Outlier Factor + One-Class SVM, K-Means archetypes, DBSCAN noise, combined into a consensus score |
| 4 | **Steam · Local AI** | Reads the *name*: plain-language search over the directory, an **incoherence** score (`observed risk − expected risk from the name`), and a small local LLM that turns each finding into a ticket | `all-MiniLM-L6-v2` embeddings + `llama3.2:3b` via Ollama, both running on CPU, fully offline |

The output is a short, ranked list of **liars** — objects whose privileges contradict their name — each with the metrics, the anomaly reason and a human-readable explanation. Everything is reviewed by an analyst before anything changes.

## Repository layout

```
.
├── Rust_in_the_Boiler_demo.ipynb   # The guided demo: one instruction and one cell per phase
├── boiler.py                       # All the machinery (collection, scoring, ML, embeddings, LLM)
├── certeu_utils.py                 # BloodHound CE API helpers used by boiler.py
├── requirements.txt                # Python dependencies
├── users.csv / groups.csv          # Pre-processed sample output (MYLAB.LOCAL lab domain)
└── mylab/                          # Sample SharpHound JSON collection of the lab domain
```

`boiler.py` is documented function by function; open it if you want to see how each step works or to tune the weights, detectors or prompts.

## Installation

### Requirements

- Python 3.10 or newer, with Jupyter (Notebook or Lab)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound) running and reachable, with an API token (only needed to process a new collection — the sample data in this repo is already processed)
- A folder with a **SharpHound JSON** collection of your domain (the `mylab/` folder is included as an example)
- [Ollama](https://ollama.com) with the `llama3.2:3b` model (phase 5.3 only)

### Steps

```bash
# 1. Clone
git clone https://github.com/lucky-luk3/CERT-EU_2026-Spotting-liars-in-your-domain.git
cd CERT-EU_2026-Spotting-liars-in-your-domain

# 2. Virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Dependencies
pip install -r requirements.txt
pip install jupyterlab

# 4. Local LLM (optional, phase 5.3)
ollama pull llama3.2:3b
ollama serve                     # if it is not already running on localhost:11434

# 5. Run
jupyter lab Rust_in_the_Boiler_demo.ipynb
```

The sentence-embedding model (`sentence-transformers/all-MiniLM-L6-v2`, ~80 MB) downloads itself on first use. To work fully offline afterwards, place a copy under `models/all-MiniLM-L6-v2/` next to `boiler.py` and it will be loaded from there.

## Usage

Open the notebook and run the cells in order. Every phase is one call:

```python
from boiler import *

# Phase 1 — Collect: BloodHound CE + SharpHound folder → users.csv / groups.csv
config_menu()                          # interactive form; or, with saved CSVs:
df_users, df_groups = load_saved()

# Phase 2 — Steel · Risk scoring
risk_ranking(df_groups, n=10)          # weights={"controllers_norm": 2} to re-weight

# Phase 3 — Steel · Graph analysis
domain_map(df_groups)
rights_origin("HELPDESK-T1@MYLAB.LOCAL")   # needs the raw JSON from phase 1

# Phase 4 — Steam · Anomaly consensus
ml = anomaly_consensus(df_groups, top_n=20)
anomaly_map(ml)                        # 3D PCA view of archetypes and outliers

# Phase 5 — Steam · Local AI
semantic_search(ml, "human resources")
incoherence(ml, n=10)                  # the liars
llm_explain(ml, n=3)                   # local LLM writes the ticket

# Phase 6 — Full circle: one group, all four layers
inspect(ml)
```

To try it immediately without a BloodHound instance, tick **Use saved data** in `config_menu()` or call `load_saved()` — the repo ships with the processed `users.csv` and `groups.csv` of the `MYLAB.LOCAL` lab domain.

### Running it on your own domain

1. Collect with SharpHound and import the ZIP into BloodHound CE.
2. Create an API token in BloodHound CE (*My Profile → API Key Management*).
3. In `config_menu()`, fill in host, port, token ID and token key, point the folder chooser to the SharpHound JSON files and press **Process data**. The first run queries the API for every user and group — on a large domain it takes a while — and saves the CSVs so later runs can skip it.

## Privacy

No data ever leaves the machine. Collection goes against your own BloodHound CE instance, the ML runs in scikit-learn, embeddings and the LLM run locally on CPU. The only internet access is the one-time download of the embedding model and the Ollama model.

## Author

**Luis F. Monge** ([@lucky-luk3](https://github.com/lucky-luk3)) — founder of [**GrexID**](https://grexid.eu), identity security for Active Directory and Entra ID: attack-path analysis, ML anomaly detection and explainable risk, built from the same ideas shown in this demo.

Questions, fixes or results from your own domain are welcome — open an issue here or get in touch through [grexid.eu](https://grexid.eu).

## License

This project — notebook, `boiler.py` and `certeu_utils.py` — is released under the [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/) licence. You are free to share and adapt it for any purpose, including commercially, as long as you give appropriate credit to Luis F. Monge / GrexID and indicate if changes were made.

Sample data in `mylab/`, `users.csv` and `groups.csv` comes from a synthetic lab domain and contains no real identities.

---

*Take away the liars… and the intruder finds nothing to grab onto.*
