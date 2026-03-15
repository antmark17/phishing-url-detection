# Phishing URL Detection

Machine learning pipeline for phishing URL detection using lexical and structural features.

![Python](https://img.shields.io/badge/python-3.10-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Overview
This project implements a machine learning pipeline for phishing URL detection based on lexical and structural features extracted directly from URLs. The objective is to distinguish phishing URLs from benign URLs without relying on HTML or page-content analysis.

The workflow is divided into four main stages:

1. **Data collection**
   - phishing URLs collected from public threat-intelligence feeds
   - benign URLs collected from large-scale benign domain lists

2. **Data cleaning**
   - removal of empty lines
   - duplicate removal
   - generation of cleaned text files for each class

3. **Feature extraction**
   - extraction of handcrafted lexical and structural features from each URL
   - generation of a structured CSV dataset

4. **Model training and evaluation**
   - preprocessing of the extracted features
   - training of multiple classifiers
   - comparison through standard classification metrics

## Project structure
```text
data/
├── raw/            # original downloaded files
├── processed/      # cleaned URL lists
└── output/         # extracted features and model results

src/
├── clean_urls.py
├── dataset_builder.py
└── feature_extractor.py

notebooks/
└── eda.ipynb
```

## Reproducibility / Quick start

Clone the repository

git clone https://github.com/<antmark17>/phishing-url-detection.git
cd phishing-url-detection

Install dependencies

pip install -r requirements.txt

Clean the raw datasets

python src/clean_urls.py

Build the feature dataset

python src/dataset_builder.py

Run the exploratory analysis and model training

open notebooks/eda.ipynb

## Dataset preparation
Two classes were built:

- **Label 1**: phishing URLs
- **Label 0**: benign URLs

After cleaning, the available datasets were:

- **Phishing URLs:** 640,801
- **Benign URLs:** 5,574,676

For the main experiment, a balanced subset of approximately **1.28 million URLs** was used:

- **640,801 phishing URLs**
- **640,801 benign URLs**

This balanced setup was chosen to reduce bias toward the majority class.

## Extracted features
The feature extractor computes lexical and structural indicators such as:

- URL length
- hostname length
- path length and path depth
- digit, letter, and special character counts
- suspicious words
- suspicious TLD presence
- shortening service detection
- IP address usage
- entropy-based measures
- typosquatting-related distance from known brands

These features were designed to capture common phishing URL patterns.

## Models used
Three models were tested:

- **Logistic Regression** as baseline model
- **Random Forest** as tree-based ensemble model
- **Extra Trees** as an additional ensemble model

The dataset was split as follows:

- **80% training set**
- **20% test set**

A stratified split was used to preserve class balance.

## Results on the large dataset
### Logistic Regression
- Accuracy: **0.987937**
- Precision: **0.999688**
- Recall: **0.976177**
- F1-score: **0.987793**

### Random Forest
- Accuracy: **0.987227**
- Precision: **0.996304**
- Recall: **0.978081**
- F1-score: **0.987109**

### Extra Trees
- Accuracy: **0.986801**
- Precision: **0.995127**
- Recall: **0.978393**
- F1-score: **0.986689**

## Brief discussion of the results
The results show that all three models are highly effective at distinguishing phishing URLs from benign URLs using only handcrafted lexical and structural features.

On the larger dataset, **Logistic Regression** achieved the best overall **accuracy** and **F1-score**, while also producing the smallest number of false positives. This indicates that the extracted features are highly informative even for a relatively simple linear classifier.

At the same time, **Random Forest** and **Extra Trees** achieved slightly higher **recall**, meaning that they were able to identify a few more phishing URLs, at the cost of producing more false positives. This highlights an important trade-off:

- **Logistic Regression** is more conservative and produces fewer false alarms
- **Random Forest** and **Extra Trees** are slightly more aggressive and capture more phishing samples

In a phishing-detection setting, this trade-off is important because false negatives correspond to malicious URLs that remain undetected, while false positives correspond to benign URLs incorrectly flagged as suspicious.

## Feature importance
The Random Forest feature importance analysis showed that the most informative features were mainly related to URL structural complexity, especially:

- number of special characters in the path
- path length
- number of slashes
- number of special characters in the full URL
- number of letters in the path
- longest path token length
- total URL length
- path depth
- decoded URL length
- URL entropy

These results are coherent with the intuition that phishing URLs tend to be longer, noisier, and structurally more complex than benign URLs.

## Important note
Although the performance is very high, the results should be interpreted with caution. The benign and phishing URLs were collected from different public sources, and this may introduce dataset bias. Therefore, the reported metrics demonstrate strong experimental performance on the constructed dataset, but not necessarily perfect generalization to every real-world scenario.


## Conclusion
This project shows that phishing URL detection can achieve very strong performance using only lexical and structural URL features. Even without analyzing webpage content, the extracted indicators provide enough information for machine learning models to discriminate effectively between phishing and benign URLs.

Among the tested models, Logistic Regression provided the best balance on the large balanced dataset, while Random Forest and Extra Trees offered slightly higher phishing recall. Overall, the pipeline is complete, reproducible, and suitable as the experimental core of a thesis project.
