"""Evaluation benchmark measuring Precision, Recall, and F1 on the curated corpus."""

from pathlib import Path
import pytest

from reposentinel.scanners.secrets import scan_directory_for_secrets


def test_evaluation_corpus_benchmark():
    corpus_root = Path(__file__).resolve().parent.parent / "corpus"
    assert corpus_root.exists(), f"Corpus root {corpus_root} does not exist"

    known_secrets_dir = corpus_root / "known_secrets"
    false_positives_dir = corpus_root / "false_positives"

    # 1. Evaluate True Positives in known_secrets directory
    tp_findings, tp_scanned = scan_directory_for_secrets(known_secrets_dir, include_placeholders=False)
    
    # In known_secrets:
    # aws_keys.py has 2 secrets (AWS access key, AWS secret key)
    # github_tokens.py has 2 secrets (GitHub PAT, Slack token)
    # private_key.pem has 1 secret (RSA Private Key)
    # database_uri.py has 1 secret (Database URI password)
    # Total expected true secrets = 6
    expected_true_secrets = 6
    true_positives = len(tp_findings)
    false_negatives = max(0, expected_true_secrets - true_positives)

    # 2. Evaluate False Positives in false_positives directory
    fp_findings, fp_scanned = scan_directory_for_secrets(false_positives_dir, include_placeholders=False)
    false_positives = len(fp_findings)
    
    # 3. Calculate Precision, Recall, and F1 Score
    precision = (
        true_positives / (true_positives + false_positives)
        if (true_positives + false_positives) > 0
        else 0.0
    )
    recall = (
        true_positives / (true_positives + false_negatives)
        if (true_positives + false_negatives) > 0
        else 0.0
    )
    f1_score = (
        (2 * precision * recall) / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    print(f"\n--- EVALUATION BENCHMARK METRICS ---")
    print(f"Scanned Corpus Files: {tp_scanned + fp_scanned}")
    print(f"True Positives Detected: {true_positives} / {expected_true_secrets}")
    print(f"False Positives Triggered: {false_positives}")
    print(f"False Negatives: {false_negatives}")
    print(f"Measured Precision: {precision * 100:.2f}%")
    print(f"Measured Recall: {recall * 100:.2f}%")
    print(f"Measured F1 Score: {f1_score * 100:.2f}%\n")

    # Benchmark assertions
    assert false_positives == 0, f"Expected 0 false positives in false_positives corpus, got {false_positives}: {fp_findings}"
    assert recall >= 0.83, f"Expected recall >= 83%, got {recall}"
    assert precision == 1.0, f"Expected precision 100%, got {precision}"
