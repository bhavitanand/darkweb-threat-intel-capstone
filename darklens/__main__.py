"""CLI: python -m darklens [demo|ingest|train|eval|serve]"""
import sys


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "demo"
    if cmd == "train":
        from .nlp.classifier import train_default
        train_default(); print("model trained")
    elif cmd == "eval":
        from .nlp.classifier import evaluate
        r = evaluate(); print({k: v for k, v in r.items() if k != "report_hybrid"}); print(r["report_hybrid"])
    elif cmd in ("ingest", "demo"):
        from . import pipeline
        from .store import db
        con = db.connect()
        print(pipeline.run(offline="--live" not in sys.argv, con=con))
        if cmd == "demo":
            print("Now run: uvicorn darklens.api.app:app   then open http://127.0.0.1:8000")
    elif cmd == "serve":
        import uvicorn
        uvicorn.run("darklens.api.app:app", host="127.0.0.1", port=8000)
    else:
        print(__doc__)


main()
