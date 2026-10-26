"""Supervised scoring support: the process-start featurizer.

Stdlib only. Nothing here is wired into :class:`DetectionRun` yet; the offline
training tool (``tools/train``) imports :mod:`.featurizer`, so training and any
later serving compute features with the same code.
"""
