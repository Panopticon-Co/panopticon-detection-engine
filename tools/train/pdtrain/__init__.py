"""Offline training pipeline for the process-start classifier.

Dev-only. Nothing under ``panopticon_detection/`` imports this package, and the
heavy dependencies it needs (``lightgbm``, ``scikit-learn``, ``numpy``) live in
the ``train`` optional extra, never in the engine's runtime dependencies.

Pipeline (each step writes hash-stamped files under ``data/``)::

    fetch -> normalize -> label -> featurize -> split -> train -> evaluate -> export -> report

See ``docs/ml/training-plan.md``.
"""
