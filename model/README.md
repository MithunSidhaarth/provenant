# Optional risk model: data, training and evaluation

**Status: not trained, not deployed.** Provenant works without any model. This folder is the reproducible
workflow for building one; nothing here runs during a normal install, and no numbers are claimed until a
real run fills in `MODEL_CARD_TEMPLATE.md`.

1. `python model/dataset.py build` writes `model/data/{train,val,test}.jsonl` from the eval corpus with labels in
   the runtime schema, split by attack family so variants of one attack never straddle train and test.
2. `python model/dataset.py validate model/data/*.jsonl` checks labels, duplicate ids, cross-split leakage and
   credential-shaped strings.
3. `python model/train_lora.py --base <checkpoint>` (GPU, `requirements-train.txt`) trains QLoRA adapters and
   writes test predictions. Candidate 14B-class bases are listed in `train_config.json`; check the licence,
   hardware need, hosting cost and latency yourself before picking one.
4. `python model/evaluate.py --predictions runs/.../test_predictions.jsonl` reports invalid outputs, accuracy,
   escalation recall and false escalation rate.
5. Serve it behind any OpenAI-compatible endpoint and write `~/.provenant/model.json` (see
   `agentshield/classifier.py`). `provenant model status` and `provenant model test` check the connection.

The seed set (163 rows) is far too small for a production model; extend it with reviewed, synthetic examples
and rebuild before training.
