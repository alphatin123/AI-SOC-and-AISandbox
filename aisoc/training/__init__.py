"""Offline training domain (Architecture 1: dual_model 訓練與推理).

    數據採集與標註 → 數據校驗與清洗 → [已知攻擊模型 | 異常檢測模型]
    → 對抗與穩健性評估 → 模型登記 + 簽名 → 模型發布閘門

``dataset`` turns captured ``conn.log`` rows plus Slips verdicts into a signed,
write-once *dataset snapshot* (the "dataset 副本" handed to the training domain).
``offline`` consumes a verified snapshot and produces a signed model release.
"""

from .dataset import (
    DATASET_CURATOR_ROLE,
    DATASET_MANIFEST_SCHEMA,
    LABEL_RULE_VERSION,
    DatasetSnapshot,
    DatasetSnapshotError,
    LabelStats,
    build_flow_records,
    build_snapshot,
    load_snapshot,
    write_snapshot,
)
from .offline import (
    CleaningReport,
    TrainingDomainError,
    TrainingResult,
    load_release_dir,
    time_split,
    train_offline,
    validate_and_clean,
    write_training_output,
)

__all__ = [
    "CleaningReport",
    "DATASET_CURATOR_ROLE",
    "DATASET_MANIFEST_SCHEMA",
    "DatasetSnapshot",
    "DatasetSnapshotError",
    "LABEL_RULE_VERSION",
    "LabelStats",
    "TrainingDomainError",
    "TrainingResult",
    "build_flow_records",
    "build_snapshot",
    "load_release_dir",
    "load_snapshot",
    "time_split",
    "train_offline",
    "validate_and_clean",
    "write_snapshot",
    "write_training_output",
]
