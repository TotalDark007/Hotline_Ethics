import math
import re
from collections import Counter, defaultdict


# Lightweight NLP helpers (no external deps)
STOPWORDS = {
    'the','and','a','an','is','are','to','of','in','on','for','with','by','at','from','as','it','this','that',
    'be','or','if','was','were','has','have','had','but','not','no','we','they','their','our','i','you','he','she','them',
    'his','her','our','your','yours','theirs','us','him','hers','ours','about','into','over','under','between','after',
    'before','above','below','up','down','out','off','again','further','then','once','here','there','when','where','why','how'
}


def tokenize(text: str):
    """Tokenize into lowercase alphabetic terms with tiny stemming and stopword removal."""
    if not text:
        return []
    words = re.findall(r"[A-Za-z]{2,}", text.lower())
    terms = []
    for w in words:
        # Lightweight stemming: strip common suffixes
        for suf in ("ing", "edly", "edly", "edly", "ed", "ly", "es", "s"):
            if w.endswith(suf) and len(w) - len(suf) >= 3:
                w = w[: -len(suf)]
                break
        if w and w not in STOPWORDS:
            terms.append(w)
    return terms


def build_idf(docs_tokens):
    """Compute IDF across documents. docs_tokens: list[list[str]]"""
    N = max(1, len(docs_tokens))
    df = Counter()
    seen = set()
    for toks in docs_tokens:
        seen.clear()
        for t in toks:
            if t not in seen:
                df[t] += 1
                seen.add(t)
    idf = {t: math.log((N + 1) / (df_t + 1)) + 1.0 for t, df_t in df.items()}
    return idf


def tfidf(tokens, idf):
    tf = Counter(tokens)
    if not tf:
        return {}
    vec = {}
    for t, c in tf.items():
        if t in idf:
            vec[t] = (c / len(tokens)) * idf[t]
    # L2 normalize
    norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
    for t in list(vec.keys()):
        vec[t] /= norm
    return vec


def cosine(v1, v2):
    if not v1 or not v2:
        return 0.0
    # iterate over smaller vector for speed
    if len(v1) > len(v2):
        v1, v2 = v2, v1
    return sum(v1.get(t, 0.0) * v2.get(t, 0.0) for t in v1.keys())


def centroid(vectors):
    """Compute normalized centroid vector from a list of vectors (dicts)."""
    acc = defaultdict(float)
    if not vectors:
        return {}
    for vec in vectors:
        for t, w in vec.items():
            acc[t] += w
    # average
    n = float(len(vectors))
    for t in list(acc.keys()):
        acc[t] /= n
    # normalize
    norm = math.sqrt(sum(v * v for v in acc.values())) or 1.0
    for t in list(acc.keys()):
        acc[t] /= norm
    return dict(acc)


def suggest_report_type_from_reports(reports, text):
    """Suggest a category using TF‑IDF centroids by class.

    Returns (label, score_points) where score_points ~= 10 * cosine similarity.
    """
    labeled = [(r.report_type, tokenize((r.report_details or ''))) for r in reports if r.report_type]
    # Need some labeled data
    if not labeled:
        return (None, 0)

    tokens_by_doc = [toks for _, toks in labeled]
    idf = build_idf(tokens_by_doc + [tokenize(text)])
    # Build vectors per class centroid
    class_vecs = defaultdict(list)
    for label, toks in labeled:
        class_vecs[label].append(tfidf(toks, idf))
    class_centroids = {label: centroid(vs) for label, vs in class_vecs.items()}

    qvec = tfidf(tokenize(text), idf)
    best_label, best_sim = None, 0.0
    for label, cvec in class_centroids.items():
        sim = cosine(qvec, cvec)
        if sim > best_sim:
            best_label, best_sim = label, sim
    # Convert to 0..10 style score to keep existing UI thresholds
    score_points = int(round(best_sim * 10))
    return (best_label, score_points)


def most_similar_reports(reports, text, exclude_id=None, top_n=5):
    """Return top_n similar reports using TF‑IDF cosine similarity.

    Each item: dict(id, status, report_type, timestamp, score [0..1 float])
    """
    docs = [(r.id, tokenize((r.report_details or ''))) for r in reports if (exclude_id is None or r.id != exclude_id)]
    if not docs:
        return []
    tokens_by_doc = [toks for _, toks in docs]
    idf = build_idf(tokens_by_doc + [tokenize(text)])
    qvec = tfidf(tokenize(text), idf)

    scored = []
    for rid, toks in docs:
        vec = tfidf(toks, idf)
        sim = cosine(qvec, vec)
        scored.append((sim, rid))
    scored.sort(key=lambda x: x[0], reverse=True)
    top_ids = {rid for _, rid in scored[:top_n]}

    # Gather full metadata for the selected reports
    results = []
    for r in reports:
        if r.id in top_ids and (exclude_id is None or r.id != exclude_id):
            results.append({
                'id': r.id,
                'status': r.status,
                'report_type': r.report_type,
                'timestamp': (r.timestamp or '').strftime('%Y-%m-%d %H:%M') if getattr(r, 'timestamp', None) else '',
                'score': next((s for s, rid in scored if rid == r.id), 0.0),
            })
    # Keep ordering by score desc
    results.sort(key=lambda x: x['score'], reverse=True)
    return results[:top_n]


def fallback_keyword_suggest(text):
    """Very small keyword-based fallback (mirrors previous behavior)."""
    keywords = {
        'Fraud': {'fraud','scam','embezzle','fake','forgery','misreport','deceive','bribe','kickback','launder','invoice','expense','accounting','theft'},
        'Harassment': {'harass','bully','abuse','threat','intimidat','verbal','physical','sexual','inappropriate','hostile','offensive','demean'},
        'Discrimination': {'discriminat','bias','racis','sexis','age','gender','religion','ethnic','disability','pregnan','unequal','harass'},
        'Safety_Violation': {'safety','hazard','unsafe','injury','accident','violation','ppe','protocol','incident','danger','risk'},
        'Conflict_of_Interest': {'conflict','interest','nepotism','favorit','outside','vendor','gift','relationship','compete','insider'},
        'Bribery': {'bribe','kickback','gift','cash','favor','payment','illicit','corrupt'},
        'Environmental_Violation': {'environment','pollut','waste','spill','emission','dump','epa','air','water','soil','hazardous'},
        'Mismanagement': {'mismanage','neglig','incompet','oversight','improper','resource','wasteful','delay','misconduct'},
    }
    toks = set(tokenize(text))
    best, best_score = None, 0
    for cat, keys in keywords.items():
        score = 0
        for k in keys:
            for t in toks:
                if t.startswith(k):
                    score += 1
        if score > best_score:
            best, best_score = cat, score
    return (best, best_score)

