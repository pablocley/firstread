"""Loop idea (applies to ml/heads/train.py): cross-fitted Platt recalibration of the combiner, folded into its weights."""
import sys
p = sys.argv[1]
s = open(p).read()
OLD = """    clf = LogisticRegression(C=float(exp["combiner"]["C"]), max_iter=4000)
    clf.fit((X - mu) / sd, y)
    w = clf.coef_[0] / sd
    b = float(clf.intercept_[0] - np.sum(clf.coef_[0] * mu / sd))"""
NEW = """    C = float(exp["combiner"]["C"])
    clf = LogisticRegression(C=C, max_iter=4000)
    clf.fit((X - mu) / sd, y)
    w = clf.coef_[0] / sd
    b = float(clf.intercept_[0] - np.sum(clf.coef_[0] * mu / sd))
    if exp.get("combiner", {}).get("recalibrate"):
        # Cross-fitted Platt scaling on calib only: out-of-fold logits from K combiners, a 1-D
        # logistic fit on them, folded into the final weights (a*z + c stays linear).
        from sklearn.model_selection import StratifiedKFold
        z = np.zeros(len(y))
        for tr, te in StratifiedKFold(n_splits=5, shuffle=True, random_state=20261026).split(X, y):
            m_, s_ = X[tr].mean(0), X[tr].std(0)
            s_ = np.where(s_ > 1e-9, s_, 1.0)
            f = LogisticRegression(C=C, max_iter=4000).fit((X[tr] - m_) / s_, y[tr])
            z[te] = f.decision_function((X[te] - m_) / s_)
        pl = LogisticRegression(C=1e6, max_iter=4000).fit(z.reshape(-1, 1), y)
        a, c0 = float(pl.coef_[0][0]), float(pl.intercept_[0])
        print(json.dumps({"platt_a": a, "platt_c": c0}))
        w, b = a * w, a * b + c0"""
assert s.count(OLD) == 1
open(p, "w").write(s.replace(OLD, NEW))
