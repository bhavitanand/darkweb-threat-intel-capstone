"""Regression and edge-case tests for 'database for sale' detection (rule DL-CRD-005).

A short post that offers a database and mentions emails/passwords used to score 'low' because the older
rule needed the sale word after the row count and did not know 'database dump'.
"""
import time

import pytest

from darklens.models import Item
from darklens.pipeline import analyse
from darklens.rules.engine import run_rules

RETAILER = (
    "Selling fresh database dump from a mid-size retailer. 1.2 million rows with emails and plaintext passwords.\n"
    "Proof available on request. Price 0.05 BTC to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh.\nContact via Session only."
)

# (text, minimum score): real offers that must be flagged.
SALES = [
    (RETAILER, 65),
    ("WTS: customer DB from a travel agency, 300k users, emails + bcrypt hashes. DM for price.", 40),
    ("Database leak, 480k records with emails and passwords, escrow accepted, 2 XMR", 40),
    # sale words after the database noun
    ("Customer database for sale with emails and passwords of 1M users", 40),
    # no sale word at all, but fresh data with credentials
    ("Fresh database with 3 million emails and passwords, contact me", 40),
    # formatting variations: upper case, Windows line endings, unicode punctuation
    ("SELLING DATABASE DUMP, 2 MILLION ROWS WITH EMAILS AND PLAINTEXT PASSWORDS. PRICE 1 BTC", 65),
    ("Selling\r\ndatabase\r\ndump with\r\nemails and passwords", 40),
    ("Selling database dump — 500k users with emails & passwords • price 0.1 BTC", 65),
]

# Ordinary or IT-flavoured posts that share words with a sale and must stay low.
EVERYDAY = [
    "Selling my old database systems textbook, 3rd edition, good condition. Pickup only.",
    "Our company database migration finished. 2 million rows moved to the new cluster overnight.",
    "For sale: used laptop, 16GB RAM, includes charger. Price negotiable.",
    "How do I stop storing plain passwords? We use bcrypt hashing on our database now, good for users.",
    # 'dump' in its everyday IT meaning
    "Attached is the heap dump from the crash. Password field was null. Selling point: fast.",
    "Security training: analysing a memory dump for passwords and credentials. Price of course is free.",
    "Core dump from the crash shows emails module failed; thread dump attached, selling it to the team as a fix.",
    # a different word that merely starts with 'db'
    "Selling dbms notes with emails of the lecturers and passwords policy summary",
    # negation
    "We are NOT selling any database; no passwords were leaked.",
    "Never selling our database, emails and passwords stay private.",
    # nothing to analyse
    "",
    "   \n\t  ",
    "db",
]


def score(text: str):
    return analyse(Item(source="manual", kind="post", title="", text=text), [], [])


@pytest.mark.parametrize("text,minimum", SALES)
def test_database_sale_posts_are_flagged(text, minimum):
    a = score(text)
    assert a.category == "credential_dump"
    assert a.score >= minimum, (a.score, [s.name for s in a.signals])
    assert any(s.name.startswith("DL-CRD-005") for s in a.signals)


@pytest.mark.parametrize("text", EVERYDAY)
def test_everyday_posts_stay_low(text):
    a = score(text)
    assert a.severity == "low", (a.score, [s.name for s in a.signals])
    assert not any(r.id == "DL-CRD-005" for r, _ in run_rules(text))


def test_database_dump_wording_matches_without_sale_words():
    assert any(r.id == "DL-CRD-002" for r, _ in run_rules("Here is the database dump from last night."))


def test_a_sale_is_never_scored_lower_than_the_same_post_without_the_offer():
    offer = score(RETAILER)
    plain = score(RETAILER.replace("Selling fresh database dump", "Notes on a database"))
    assert offer.score >= plain.score


def test_scores_stay_in_range_and_evidence_is_short():
    for text, _ in SALES:
        a = score(text)
        assert 0 <= a.score <= 100
        for s in a.signals:
            assert len(s.evidence) <= 120


def test_hostile_and_huge_inputs_finish_quickly():
    """Rules use bounded gaps, so even repeated trigger words must not cause catastrophic backtracking."""
    hostile = [
        "selling " + "database " * 20000 + "x",
        ("selling database dump " + "a" * 100 + " ") * 2000,
        "1 rows " * 20000,
        "not " * 50000,
        "(" * 30000,
    ]
    for text in hostile:
        start = time.time()
        a = score(text)
        assert time.time() - start < 15, f"too slow on input starting {text[:20]!r}"
        assert 0 <= a.score <= 100


def test_non_latin_text_does_not_crash():
    for text in ["база данных продажа", "数据库出售 邮箱 密码", "\U0001f512\U0001f4be\U0001f4a5"]:
        assert 0 <= score(text).score <= 100
