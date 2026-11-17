"""CLI: python -m darklens <command>

  demo                      load the offline demo data
  ingest [--live]           collect (demo data by default, real feeds with --live)
  train                     retrain the classifier
  eval                      score the classifier on held-out synthetic templates
  eval --csv FILE           score it on your own labelled data (columns: text,label)
  eval --feedback           score it on labels given by reviewers in the app
  eval --live-claims        check it against real Ransomware.live claims (needs network)
  eval --real                 honest real-data test: train before 2026, measure on breaches and advisories never seen
  data build                  fetch the real breach write-ups and advisories used for training (needs the internet)
  eval --csv FILE --pipeline  score the whole product (alerts, "Not sure", false alarms) on your labelled data
  label pool                gather public text for a real labelled set  (see docs/labelling.md)
  label sheets NAMES        write one labelling sheet per person, e.g. label sheets bhavit,krish,naisha
  label check               check the filled-in sheets and measure how much the labellers agree
  label split               merge the sheets and split into a tuning half and an untouched test half
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
    elif cmd == "data":
        from .nlp import realdata
        if len(sys.argv) > 2 and sys.argv[2] == "build":
            print(realdata.build())
        else:
            print("python -m darklens data build   # fetch the real breach write-ups and advisories into data/real_labelled/")
    elif cmd == "eval":
        from .nlp.classifier import evaluate, get_classifier
        if "--real" in sys.argv:
            from .nlp import realeval
            for k, v in realeval.holdout_report().items():
                print(f"{k}: {v}")
        elif "--csv" in sys.argv and "--pipeline" in sys.argv:
            from . import pipeline
            from .nlp import realeval
            r = realeval.score_pipeline(get_classifier(), *realeval.load_csv(_opt("--csv")), analyse=pipeline.analyse)
            print(f"examples: {r['n']}  classes: {r['class_counts']}")
            print("macro-F1 (whole pipeline):", r["macro_f1"], " accuracy:", r["accuracy"])
            print(f"classes with enough examples to score fairly (10+): {r['classes_scored']}  ->  macro-F1 on those: {r['macro_f1_scored_classes']}")
            if r["classes_too_few_to_score"]:
                print("NOT MEASURED (fewer than 10 examples, do not quote a score for these):", r["classes_too_few_to_score"])
            for k in ("threats_missed_rate", "threats_wrong_type_rate", "false_alarm_rate", "false_alarm_medium_or_higher_rate"):
                print(f"{k}: {r[k]}")
            print("severity of detected threats:", r["severity_of_detected_threats"])
            print("most common confusions (truth -> predicted, count):", r["top_confusions"])
            if r["warning"]:
                print("NOTE:", r["warning"])
            print(r["report"])
        elif "--csv" in sys.argv:
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
    elif cmd == "label":
        from .labelling.cli import run
        sys.exit(run(sys.argv[2:]))
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
