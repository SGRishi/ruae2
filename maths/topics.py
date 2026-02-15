from __future__ import annotations

import math
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Topic:
    name: str
    keywords: list[str]


FALLBACK_TOPICS: list[Topic] = [
    Topic(
        name="Algebra",
        keywords=[
            "factorise",
            "simplify",
            "expand",
            "quadratic",
            "simultaneous",
            "inequality",
            "complete the square",
            "surds",
            "binomial",
            "sequence",
            "series",
        ],
    ),
    Topic(
        name="Functions",
        keywords=[
            "function",
            "domain",
            "range",
            "inverse",
            "composite",
            "graph",
            "sketch",
            "asymptote",
            "transform",
        ],
    ),
    Topic(
        name="Trigonometry",
        keywords=[
            "sin",
            "cos",
            "tan",
            "radians",
            "degrees",
            "trigonometric",
            "identities",
            "solve",
            "triangle",
            "bearing",
        ],
    ),
    Topic(
        name="Calculus",
        keywords=[
            "differentiate",
            "derivative",
            "gradient",
            "tangent",
            "integration",
            "integrate",
            "area",
            "rate of change",
            "stationary",
            "maximum",
            "minimum",
            "optimization",
        ],
    ),
    Topic(
        name="Vectors",
        keywords=[
            "vector",
            "magnitude",
            "unit vector",
            "dot product",
            "scalar product",
            "intersection",
            "line",
            "plane",
        ],
    ),
    Topic(
        name="Logs/Exponentials",
        keywords=[
            "log",
            "ln",
            "exponential",
            "e^",
            "index law",
            "change of base",
        ],
    ),
    Topic(
        name="Statistics",
        keywords=[
            "probability",
            "mean",
            "variance",
            "standard deviation",
            "normal",
            "binomial",
            "correlation",
        ],
    ),
]


_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokenize(text: str) -> list[str]:
    return _TOKEN_RE.findall((text or "").lower())


def _build_idf(docs: list[list[str]]) -> dict[str, float]:
    n = len(docs) or 1
    df: dict[str, int] = {}
    for doc in docs:
        for t in set(doc):
            df[t] = df.get(t, 0) + 1
    return {t: math.log((n + 1) / (df_t + 1)) + 1.0 for t, df_t in df.items()}


def _tfidf(tokens: list[str], idf: dict[str, float]) -> dict[str, float]:
    if not tokens:
        return {}
    counts: dict[str, int] = {}
    for t in tokens:
        counts[t] = counts.get(t, 0) + 1
    total = float(len(tokens))
    vec: dict[str, float] = {}
    for t, c in counts.items():
        if t not in idf:
            continue
        vec[t] = (c / total) * idf[t]
    return vec


def _cosine(a: dict[str, float], b: dict[str, float]) -> float:
    if not a or not b:
        return 0.0
    dot = 0.0
    for k, v in a.items():
        dot += v * b.get(k, 0.0)
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


def classify_topic(text: str, topics: list[Topic] | None = None) -> tuple[str, float]:
    """Return (topic_name, confidence in [0,1])."""
    topics = topics or FALLBACK_TOPICS
    q_tokens = _tokenize(text)
    if not q_tokens:
        return ("", 0.0)

    topic_docs = []
    for topic in topics:
        doc_tokens = []
        for kw in topic.keywords:
            doc_tokens.extend(_tokenize(kw))
        topic_docs.append(doc_tokens)

    idf = _build_idf(topic_docs + [q_tokens])
    q_vec = _tfidf(q_tokens, idf)

    best_name = ""
    best_score = 0.0
    scores = []
    for topic, doc_tokens in zip(topics, topic_docs, strict=False):
        t_vec = _tfidf(doc_tokens, idf)
        score = _cosine(q_vec, t_vec)
        scores.append(score)
        if score > best_score:
            best_score = score
            best_name = topic.name

    # Simple normalization for a pseudo-confidence.
    total = sum(scores) or 0.0
    confidence = (best_score / total) if total > 0 else 0.0
    return (best_name, float(confidence))

