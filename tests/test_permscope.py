import unittest
from permscope.cli import analyze, main

WF = """
on: push
permissions:
  contents: write
  pull-requests: write
jobs:
  a:
    runs-on: x
    steps:
      - uses: actions/checkout@v4
      - name: push
        run: |
          git commit -am x
          git push
  b:
    permissions: {contents: read}
    steps:
      - uses: softprops/action-gh-release@v2
"""

class T(unittest.TestCase):
    def test_excess_and_missing(self):
        r = {x["job"]: x for x in analyze("w.yml", WF)}
        kinds_a = {(i["kind"], i.get("scope")) for i in r["a"]["issues"]}
        self.assertIn(("excess", "pull-requests"), kinds_a)
        self.assertNotIn(("excess", "contents"), kinds_a)
        self.assertEqual(r["a"]["needed"], {"contents": "write"})
        kinds_b = {(i["kind"], i.get("scope")) for i in r["b"]["issues"]}
        self.assertIn(("missing", "contents"), kinds_b)

    def test_no_permissions(self):
        r = analyze("w.yml", "on: push\njobs:\n  t:\n    steps:\n      - run: echo hi\n")
        self.assertEqual(r[0]["issues"][0]["kind"], "no-permissions")

    def test_write_all_and_oidc(self):
        wf = "permissions: write-all\njobs:\n  d:\n    steps:\n      - uses: aws-actions/configure-aws-credentials@v4\n"
        r = analyze("w.yml", wf)[0]
        self.assertEqual(r["issues"][0]["kind"], "write-all")
        self.assertEqual(r["needed"], {"id-token": "write"})

    def test_examples_fail_on(self):
        self.assertEqual(main(["examples", "--fail-on", "high"]), 1)

if __name__ == "__main__":
    unittest.main()
