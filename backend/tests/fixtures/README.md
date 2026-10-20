# Detection evaluation data

`detection_evaluation.json` is a 41-message synthetic labeled regression set (20 phishing, 21 legitimate). It is designed to catch changes in the current heuristic rules and is not a substitute for a representative, consented production corpus. The evaluation prints false positives and missed phishing separately and fails if the set size or the precision/recall floors regress. Add carefully reviewed, anonymized cases as the team collects them; preserve the labels and document why each case is labeled.
