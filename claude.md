# IoT Botnet Detector (Computer Networks project)

## Goal
AI-based detection of IoT botnets from communication behavior and traffic patterns.
Building ONE integrated system, step by step (not separate phases).

## Architecture
Traffic (CSV / live simulator) -> feature extraction -> detection engine
(Random Forest + Autoencoder + per-device profile) -> SHAP explainer + graph/C2 analysis
-> mitigation -> FastAPI backend -> Streamlit dashboard.

## Build steps
1. Setup, synthetic data generator, Random Forest  (DONE / in progress)
2. Autoencoder + unified detector class (src/detector.py)
3. FastAPI backend
4. Streamlit dashboard (Overview, Devices, Graph, Live, Explain tabs)
5. SHAP explanations
6. Graph / C2 detection with NetworkX
7. Live traffic simulator + streaming
8. Auto-mitigation (iptables-style rules) + Docker

## Structure
src/config.py (FEATURES, paths), src/data_gen.py, src/train_rf.py, data/, models/

## Notes
- Windows + PowerShell, venv in ./venv
- Run modules from project root: python -m src.data_gen
- Synthetic data has 40 devices, 8 infected; attack types: scan, flood, c2.
  c2 beacons are quiet, so the RF is expected to miss them; the autoencoder
  and graph steps are meant to fix that.