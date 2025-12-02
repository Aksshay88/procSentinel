from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional, Protocol
import json
import math
import pathlib

from .features import extract_features, FEATURE_NAMES
from .models import ProcInfo

try:
    from sklearn.ensemble import IsolationForest  # type: ignore
    HAVE_SKLEARN = True
except ImportError:
    HAVE_SKLEARN = False


class AnomalyModel(Protocol):
    def fit(self, X: List[List[float]]) -> None: ...
    def anomaly_score(self, x: List[float]) -> float: ...
    def save(self, path: pathlib.Path) -> None: ...
    @classmethod
    def load(cls, path: pathlib.Path) -> "AnomalyModel": ...


@dataclass
class ZScoreModel(AnomalyModel):
    means: List[float] = field(default_factory=list)
    stds: List[float] = field(default_factory=list)

    def fit(self, X: List[List[float]]) -> None:
        if not X:
            self.means = [0.0] * len(FEATURE_NAMES)
            self.stds = [1.0] * len(FEATURE_NAMES)
            return
        n = len(X)
        d = len(X[0])
        self.means = [0.0] * d
        self.stds = [0.0] * d

        # mean
        for row in X:
            for j, v in enumerate(row):
                self.means[j] += v
        self.means = [m / n for m in self.means]

        # std
        for row in X:
            for j, v in enumerate(row):
                self.stds[j] += (v - self.means[j]) ** 2
        self.stds = [math.sqrt(s / max(n - 1, 1)) or 1.0 for s in self.stds]

    def anomaly_score(self, x: List[float]) -> float:
        if not self.means or not self.stds:
            return 0.0
        zsum = 0.0
        for v, m, s in zip(x, self.means, self.stds):
            z = abs((v - m) / s)
            zsum += z
        # normalize somewhat: larger = more anomalous, roughly 0..10 range
        return min(zsum / len(x), 10.0) / 10.0  # 0..1

    def save(self, path: pathlib.Path) -> None:
        data = {"means": self.means, "stds": self.stds}
        path.write_text(json.dumps(data))

    @classmethod
    def load(cls, path: pathlib.Path) -> "ZScoreModel":
        data = json.loads(path.read_text())
        return cls(means=data["means"], stds=data["stds"])


@dataclass
class IsolationForestModel(AnomalyModel):
    model: Optional[IsolationForest] = None

    def fit(self, X: List[List[float]]) -> None:
        if not HAVE_SKLEARN:
            raise RuntimeError("scikit-learn is not installed")
        self.model = IsolationForest(contamination="auto", random_state=42)
        if X:
            self.model.fit(X)

    def anomaly_score(self, x: List[float]) -> float:
        if self.model is None:
            return 0.0
        # score_samples returns the opposite of the anomaly score
        score = self.model.score_samples([x])[0]
        # normalize to 0..1 where 1 is most anomalous
        return max(0.0, -score)

    def save(self, path: pathlib.Path) -> None:
        if not HAVE_SKLEARN:
            raise RuntimeError("scikit-learn is not installed")
        if self.model is None:
            return
        import joblib  # type: ignore
        joblib.dump(self.model, path)

    @classmethod
    def load(cls, path: pathlib.Path) -> "IsolationForestModel":
        if not HAVE_SKLEARN:
            raise RuntimeError("scikit-learn is not installed")
        import joblib  # type: ignore
        model = joblib.load(path)
        return cls(model=model)


def choose_model(use_sklearn: bool) -> AnomalyModel:
    if use_sklearn:
        if not HAVE_SKLEARN:
            raise RuntimeError("scikit-learn is not installed, but use_sklearn=True")
        return IsolationForestModel()
    return ZScoreModel()


def train_model(
    procs: List[ProcInfo],
    output_path: pathlib.Path,
    model_type: str = "zscore",
) -> AnomalyModel:
    """Train a model on a list of processes."""
    features = [extract_features(p) for p in procs]
    if model_type == "isoforest":
        if not HAVE_SKLEARN:
            raise ValueError("scikit-learn is required for isoforest")
        model: AnomalyModel = IsolationForestModel()
    else:
        model = ZScoreModel()
    model.fit(features)
    model.save(output_path)
    return model


def load_model(path: pathlib.Path) -> AnomalyModel:
    """
    Load a model, guessing the type from the file extension.
    - .json -> ZScoreModel
    - .joblib -> IsolationForestModel
    """
    if path.suffix == ".json":
        return ZScoreModel.load(path)
    if path.suffix == ".joblib":
        return IsolationForestModel.load(path)
    raise ValueError(f"Unknown model type for {path}")