# Publishing this repository

The history is already built: 18 commits on `main`, all authored as
`suhanii-an <ansuhani05@gmail.com>`. Nothing needs rewriting.

## 1. Check what you are about to publish

```bash
git log --oneline
git log --format='%an <%ae>' | sort -u     # should print only your name
git ls-files | grep -i '\.env$'            # should print nothing
```

The third one matters most. `.env` is gitignored and the CI pipeline fails the
build if a credential file is ever tracked, but check it once by hand before the
first push.

## 2. Create the repository

Empty, with no README, licence or .gitignore — this repo already has all three
and GitHub's versions would collide.

```bash
gh repo create sentinel-x --public --source=. --remote=origin --push
```

or, without the `gh` CLI:

```bash
git remote add origin https://github.com/suhanii-an/sentinel-x.git
git push -u origin main
```

## 3. After the first push

- **Settings → Actions**: confirm workflows are enabled. The first run takes
  ~6 minutes — backend on SQLite and Postgres, detection rules, frontend,
  browser tests, dependency audit, both container images.
- **Settings → Security**: turn on Dependabot alerts and secret scanning. This
  is a security project; a repository that does not use the free security
  features is a bad look.
- **About** (top right of the repo page): add the description and topics.
  Suggested description:

  > Miniature SOC: attack simulation, deterministic detection, correlation into
  > incidents, ATT&CK mapping, threat hunting and grounded AI investigation.
  > Measured at 0.973 precision / 0.900 recall against a labelled dataset.

  Suggested topics: `security` `detection-engineering` `siem` `soc`
  `mitre-attack` `threat-hunting` `incident-response` `fastapi` `react`
  `prompt-injection`

- **Branch protection on `main`**: require the CI checks to pass. Optional for a
  solo project, but it means the badge on the README is load-bearing.

## 4. Adding screenshots

The README is deliberately text-only so that every claim in it is verifiable
from the code. If you add screenshots, put them in `docs/images/` and caption
them with what they show. Do not add a screenshot of a feature that does not
work — the project's first rule is that nothing is faked, and that applies to
the README too.

Good candidates, in order: the incident detail page with the attack graph, the
ATT&CK coverage matrix with its uncovered techniques visible, and the Evaluation
page showing the confusion matrix and the ambiguous-class weakness.

## 5. Writing the LinkedIn post

Some notes, since the temptation is to describe the feature list.

The feature list is the least interesting thing here. What distinguishes this
from every other "I built a SIEM dashboard" project is the parts that report
their own weaknesses:

- Detection performance is **measured** by a harness in the repository, against
  a labelled dataset in the repository, reproducible with one command. Not
  asserted in a README.
- The dataset has a third class — *ambiguous* — for benign activity that
  legitimately resembles an attack. All 26 of those currently alert, and that is
  on the Evaluation page rather than in a footnote. Being able to say "here is
  where my detections are weak, and here is the number" is a more senior thing
  to demonstrate than a high F1.
- The AI never decides anything. Detection, correlation, scoring and reporting
  run with no model configured. When the assistant is enabled, every citation it
  makes is checked against the evidence it was actually given, and fabricated
  ones are stripped and shown to the analyst.
- `docs/threat-model.md` has a section titled "What this does NOT defend
  against". That section is the reason the rest of the document is credible.

If you want one line: *the interesting part of building a detection platform is
not making it detect things, it is making it honest about what it misses.*
