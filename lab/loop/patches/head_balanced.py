"""Loop idea (applies to ml/heads/train.py): class-balanced logistic head (experiment key heads.class_weight)."""
import sys
p = sys.argv[1]
s = open(p).read()
OLD = """    clf = LogisticRegression(C=float(exp["heads"]["C"]), max_iter=4000)
    clf.fit(Xtr, ytr)"""
NEW = """    clf = LogisticRegression(C=float(exp["heads"]["C"]), max_iter=4000,
                             class_weight=exp["heads"].get("class_weight") or None)
    clf.fit(Xtr, ytr)"""
assert s.count(OLD) == 1
open(p, "w").write(s.replace(OLD, NEW))
