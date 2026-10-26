"""Loop idea (applied to ml/heads/train.py in tag oct26b, kept, and on main since): L1-penalised combiner (combiner.l1_ratio)."""
import sys
p = sys.argv[1]
s = open(p).read()
OLD = """    clf = LogisticRegression(C=float(exp["combiner"]["C"]), max_iter=4000)
    clf.fit((X - mu) / sd, y)"""
NEW = """    l1 = float(exp["combiner"].get("l1_ratio", 0.0))
    clf = LogisticRegression(C=float(exp["combiner"]["C"]), max_iter=4000, l1_ratio=l1,
                             solver="saga" if l1 > 0 else "lbfgs")
    clf.fit((X - mu) / sd, y)"""
assert s.count(OLD) == 1
open(p, "w").write(s.replace(OLD, NEW))
