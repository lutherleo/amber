"""Reproducible ML: a Random Forest on the UCI Wine dataset, scored by 5-fold CV (scikit-learn).

Stands in for a data-science research result. With fixed random_state the cross-validated accuracy is
deterministic, so the recorded score reproduces exactly. Exercises the numpy + scipy + scikit-learn
stack, so the capture records a rich set of third-party library objects.
"""
from __future__ import annotations

import json

import numpy as np
import sklearn
from sklearn.datasets import load_wine
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score


def main() -> None:
    x, y = load_wine(return_X_y=True)
    clf = RandomForestClassifier(n_estimators=200, random_state=0)
    scores = cross_val_score(clf, x, y, cv=5)
    result = {
        "cv_mean_accuracy": float(scores.mean()),
        "cv_std": float(scores.std()),
        "n_samples": int(x.shape[0]),
        "n_features": int(x.shape[1]),
        "numpy_version": np.__version__,
        "sklearn_version": sklearn.__version__,
    }
    with open("result.json", "w") as fh:
        json.dump(result, fh, indent=2, sort_keys=True)
    print("sklearn wine complete:", result)


if __name__ == "__main__":
    main()
