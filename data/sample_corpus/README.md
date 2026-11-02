# data/sample_corpus/

Eight short, hand-written plaintext files for **demonstrating** the vault:
unlocking, uploading, searching a keyword, opening a decrypted file, and
showing the "what the cloud sees" inspector holding nothing but ciphertext.

They exist because architecture Section 11 calls for them (`data/sample_corpus/
-- small plaintext files to demo on`) and because pseudo-word text is useless in
a live demo: nobody is convinced by searching for `qekba`, and everybody follows
a search for `invoice`.

**These files are demo input, not measurement data.** No number in
`docs/performance_report.html` comes from this directory. The benchmark corpus is
generated deterministically by `benchmarks/harness/corpus.py` from a fixed seed,
so it is identical on every machine; this one was written by hand and is here to
be read by a human.

Useful demo keywords. The counts below were produced by running the vault's own
`client/tokenizer.py` over these files, not by reading them by eye:

| Keyword | Files | Which |
|---|---|---|
| `invoice` | 2 | budget_notes.txt, invoice_march.txt |
| `encryption` | 4 | project_brief.txt, reading_list.txt, security_review.txt, thesis_outline.txt |
| `argon2id` | 1 | security_review.txt |
| `deadline` | 3 | meeting_minutes.txt, project_brief.txt, travel_plan.txt |
| `benchmark` | 4 | budget_notes.txt, invoice_march.txt, meeting_minutes.txt, project_brief.txt |
| `zanzibar` | 1 | travel_plan.txt |

`zanzibar` is a deliberate single-match example and `encryption` a deliberate
multi-match one, so a demo can show both the one-hit and the several-hit path.
