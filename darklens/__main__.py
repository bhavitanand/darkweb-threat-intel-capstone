"""CLI: python -m darklens <command>

  demo                      load the offline demo data
  ingest [--live]           collect (demo data by default, real feeds with --live)
  train                     retrain the classifier
  eval                      score the classifier on held-out synthetic templates
  eval --csv FILE           score it on your own labelled data (columns: text,label)
  eval --feedback           score it on labels given by reviewers in the app
  eval --live-claims        check it against real Ransomware.live claims (needs network)
  notify-test               send a test message on the configured alert channels
  serve                     run the API and dashboard on http://127.0.0.1:8000
"""
import sys


def _opt(name: str):
    return sys.argv[sys.argv.index(name) + 1] if name in sys.argv and sys.argv.index(name) + 1 < len(sys.argv) else None


def _print_scores(r: dict) -> None:
    print(f"examples: {r['n']}  classes: {r.get('class_counts')}")
    print("macro-F1:", r["macro_f1"], " hybrid accuracy:", r.get("accuracy"))
    if r.get("warning"):
        print("NOTE:", r["warning"])
    print(r.get("report", ""))


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "demo"
    if cmd == "train":
        from .nlp.classifier import train_default
        train_default(); print("model trained")
    elif cmd == "eval":
        from .nlp.classifier import evaluate, get_classifier
        if "--csv" in sys.argv:
            from .nlp import realeval
            _print_scores(realeval.score_labelled(get_classifier(), *realeval.load_csv(_opt("--csv"))))
        elif "--feedback" in sys.argv:
            from .nlp import realeval
            from .store import db
            r = realeval.score_feedback(get_classifier(), db.feedback_all(db.connect()))
            print(f"reviewers gave feedback on {r['n']} alerts; agreement with the system: {r.get('agreement')}")
            if "macro_f1" in r:
                _print_scores(r)
            elif r.get("warning"):
                print(r["warning"])
        elif "--live-claims" in sys.argv:
            import json
            from . import pipeline
            from .collectors import ransomware_live
            from .nlp import realeval
            r = realeval.live_claims_check(get_classifier(), ransomware_live.fetch(offline=False, limit=100), pipeline.analyse)
            print(json.dumps(r, indent=2))
        else:
            r = evaluate(); print({k: v for k, v in r.items() if k != "report_hybrid"}); print(r["report_hybrid"])
    elif cmd in ("ingest", "demo"):
        from . import ingest
        state = ingest.run_ingest(live="--live" in sys.argv and cmd == "ingest")
        print({k: state[k] for k in ("mode", "items", "alerts", "ok")}, [f"{s['source']}: {s['status']}" for s in state["sources"]])
        if cmd == "demo":
            print("Now run: python -m darklens serve   then open http://127.0.0.1:8000")
    elif cmd == "notify-test":
        from . import notify
        chans = notify.channels()
        if not chans:
            print("No channel configured. Set ALERT_WEBHOOK_URL, or SMTP_HOST and ALERT_EMAIL_TO.")
            return
        for ch in chans:
            notify._send(ch, "DarkLens test message: alerts are working.")
            print(f"sent on {ch}")
    elif cmd == "serve":
        import uvicorn
        uvicorn.run("darklens.api.app:app", host="127.0.0.1", port=8000)
    else:
        print(__doc__)


main()
