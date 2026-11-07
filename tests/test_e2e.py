"""Acceptance checks from the pitch deck's "Done means" line. Run: python -m unittest discover -s tests -v"""
import io
import os
import sys
import time
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.pop("VULTR_INFERENCE_API_KEY", None)

from traceback_core import fixtures
from traceback_core.investigator import investigate, run_containment
from traceback_core.snapshot import SnapshotError, load_zip
import app as appmod


class Core(unittest.TestCase):
    def test_known_cause_real_result_traceable_evidence(self):
        r = investigate(*fixtures.known_bug(), "why?", "")
        self.assertEqual(r["verdict"], "confirmed")
        f = r["finding"]
        self.assertEqual(f["confidence"], "high")
        self.assertIn("DATABASE_URL", f["title"])
        self.assertIn("-DB_URL=", f["patch"])
        self.assertIn("+DATABASE_URL=", f["patch"])
        src = next(e for e in f["evidence"] if e["kind"] == "source")
        self.assertEqual((src["ref"]["path"], src["ref"]["line"]), (".env.example", 4))  # the deck's example
        # unrelated noise changes must NOT be confirmed
        by = {c["title"]: c for c in r["candidates"]}
        self.assertFalse(by["File modified: app.py"]["passed"])
        self.assertFalse(by["Dependency changed: flask ==3.0.0 → ==3.0.2"]["passed"])
        self.assertTrue(r["sandbox"]["all_workspaces_destroyed"])

    def test_patch_is_not_applied(self):
        b, a = fixtures.known_bug()
        before_after = dict(a)
        investigate(b, a, "why?", "")
        self.assertEqual(a, before_after)

    def test_inconclusive_when_before_also_fails(self):
        r = investigate(*fixtures.inconclusive(), "why?", "")
        self.assertEqual(r["verdict"], "inconclusive")
        self.assertEqual(r["finding"]["confidence"], "low")
        self.assertIsNone(r["finding"]["patch"])

    def test_no_failure_reproduced(self):
        b, _ = fixtures.known_bug()
        r = investigate(b, dict(b, **{"README.md": b"changed\n"}), "why?", "")
        self.assertEqual(r["verdict"], "no_failure_reproduced")

    def test_containment(self):
        r = run_containment()
        self.assertEqual(r["verdict"], "contained", r["checks"])
        kinds = {v["event"].split(".")[0] for v in r["violations"]}
        self.assertTrue({"file", "network", "process"} <= kinds)

    def test_zip_slip_rejected(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("../evil.py", "x")
        p = "/tmp/_evil.zip"
        with open(p, "wb") as fh:
            fh.write(buf.getvalue())
        with self.assertRaises(SnapshotError):
            load_zip(p)


class Api(unittest.TestCase):
    def wait(self, c, jid):
        for _ in range(100):
            j = c.get(f"/api/runs/{jid}").get_json()
            if j["status"] != "running":
                return j
            time.sleep(0.2)
        self.fail("timeout")

    def test_upload_flow_and_evidence_viewer(self):
        c = appmod.app.test_client()
        data = {k: (io.BytesIO(c.get(f"/api/fixtures/known-bug/{k}.zip").data), f"{k}.zip") for k in ("before", "after")}
        data["question"] = "why?"
        jid = c.post("/api/runs", data=data, content_type="multipart/form-data").get_json()["id"]
        j = self.wait(c, jid)
        self.assertEqual(j["report"]["verdict"], "confirmed")
        f = c.get(f"/api/runs/{jid}/file?side=after&path=.env.example").get_json()
        self.assertEqual(f["lines"][3], "DB_URL=sqlite:///orbit.db")
        self.assertEqual(c.get(f"/api/runs/{jid}/file?side=after&path=../../etc/passwd").status_code, 404)
        self.assertEqual(c.get(f"/api/runs/{jid}/patch.diff").status_code, 200)

    def test_bad_upload(self):
        c = appmod.app.test_client()
        r = c.post("/api/runs", data={"before": (io.BytesIO(b"nope"), "a.zip"), "after": (io.BytesIO(b"nope"), "b.zip")},
                   content_type="multipart/form-data")
        self.assertEqual(r.status_code, 400)


if __name__ == "__main__":
    unittest.main()
