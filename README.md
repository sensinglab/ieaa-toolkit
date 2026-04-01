# MoniCrowd IEAA  
**Information Elements Automatic Analyser for Wi-Fi Fingerprinting**

---

## Overview

This repository provides the **Information Elements Automatic Analyser (IEAA)**, a tool refactored within the **MoniCrowd project** to support Wi-Fi-based device fingerprinting under MAC address randomization.

The tool analyses **Wi-Fi probe requests**, extracting and evaluating **Information Elements (IEs)** to identify stable and discriminative features for device differentiation. It is designed to support the development and evaluation of fingerprinting techniques for **privacy-preserving crowd monitoring**.

---

## Motivation

Modern mobile devices implement **MAC address randomization**, which prevents reliable device counting using traditional identifiers.

The IEAA addresses this challenge by:
- analysing probe request structure beyond MAC addresses  
- extracting relevant Information Elements (IEs)  
- identifying features suitable for robust fingerprinting  

---

## Key Features

- Fine-grained extraction of Information Elements (IEs)  
- Evaluation of feature stability and uniqueness  
- Support for fingerprint generation pipelines  
- Compatibility with controlled and real-world datasets  
- Privacy-preserving by design (no personal data required)  

---

## Role in the System

The IEAA is part of the Wi-Fi sensing pipeline:
```
Wi-Fi Probe Requests
↓
IE Analysis (IEAA)
↓
Fingerprinting
↓
Device Counting
↓
Crowd Estimation
```
It improves the **feature engineering stage**, which is critical for accurate device counting.

---

## Data Sources

The tool can be used with:

- **Controlled datasets**  
  (e.g., captures collected in Faraday cage environments)

- **Real-world datasets**  
  (passive Wi-Fi monitoring in deployment scenarios)
