# Model card: provenant-risk-<size>-<date>

> Fill every field from a real run. Leave a field as "not measured" rather than estimating it.

| Field | Value |
|---|---|
| Base model and revision | |
| Base model licence (checked on) | |
| Fine-tuning method | QLoRA, config `model/train_config.json` at commit `<sha>` |
| Training data | `model/data/train.jsonl` built by `model/dataset.py` at commit `<sha>` (rows, groups) |
| Hardware and wall time | |
| Training cost | |
| Serving setup and p50/p95 latency | |

## Intended use
Advisory risk labels for tool calls that Provenant's deterministic policy has already allowed. The label can send
a call to a human only when the operator's policy opts in (`model_assist.escalate_on`). It can never allow a call.

## Out of scope
Authorizing tool calls; replacing the deterministic policy; classifying content outside a single tool call.

## Evaluation (`model/evaluate.py` on `model/data/test.jsonl`)
| Metric | Value |
|---|---|
| invalid outputs | |
| risk_level accuracy | |
| category accuracy | |
| escalation recall (high/critical) | |
| false escalation rate (benign) | |

## Known limitations
- The seed dataset is small (163 rows from the eval corpus) and synthetic. Results on it do not predict real traffic.
- A model can be prompt-injected by argument text. The runtime treats its output as advisory for this reason.

## Privacy
Inputs are the minimal payload from `agentshield/classifier.py`: tool name, policy category, argument names and,
with `send: "redacted"`, secret-redacted argument text truncated to `max_chars`. `send: "metadata"` sends no values.
