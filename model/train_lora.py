"""Fine-tune the optional risk classifier with QLoRA. Not part of the Provenant install: it needs a GPU and
`pip install -r model/requirements-train.txt`. Nothing in Provenant imports this file.

    python model/dataset.py build
    python model/train_lora.py --config model/train_config.json --base Qwen/Qwen2.5-14B-Instruct --out runs/risk-14b
    python model/evaluate.py --predictions runs/risk-14b/test_predictions.jsonl

The prompt is the runtime's own SYSTEM_PROMPT and payload, and the target is the label JSON, so the trained model
answers in exactly the schema agentshield/classifier.py validates.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from agentshield.classifier import SYSTEM_PROMPT  # noqa: E402


def rows(path: str) -> list[dict]:
    return [json.loads(l) for l in (ROOT / path).read_text(encoding="utf-8").splitlines() if l.strip()]


def to_chat(r: dict) -> list[dict]:
    return [{"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(r["input"], ensure_ascii=False)},
            {"role": "assistant", "content": json.dumps(r["label"])}]


def main(argv: list[str]) -> int:
    cfg = json.loads(Path(argv[argv.index("--config") + 1] if "--config" in argv else ROOT / "model/train_config.json").read_text())
    base = argv[argv.index("--base") + 1] if "--base" in argv else cfg["base_model_candidates"][0]["id"]
    out = Path(argv[argv.index("--out") + 1] if "--out" in argv else "runs/risk")
    try:
        import torch
        from datasets import Dataset
        from peft import LoraConfig
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
        from trl import SFTConfig, SFTTrainer
    except ImportError as exc:
        print(f"training dependencies missing ({exc.name}); pip install -r model/requirements-train.txt")
        return 2
    tok = AutoTokenizer.from_pretrained(base)
    model = AutoModelForCausalLM.from_pretrained(base, device_map="auto", quantization_config=BitsAndBytesConfig(
        load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_compute_dtype=torch.bfloat16))
    data = {k: Dataset.from_list([{"messages": to_chat(r)} for r in rows(cfg["data"][k])]) for k in ("train", "val")}
    t, l = cfg["training"], cfg["lora"]
    trainer = SFTTrainer(model=model, processing_class=tok, train_dataset=data["train"], eval_dataset=data["val"],
                         peft_config=LoraConfig(r=l["r"], lora_alpha=l["alpha"], lora_dropout=l["dropout"],
                                                target_modules=l["target_modules"], task_type="CAUSAL_LM"),
                         args=SFTConfig(output_dir=str(out), num_train_epochs=t["epochs"], learning_rate=t["learning_rate"],
                                        per_device_train_batch_size=t["batch_size"], gradient_accumulation_steps=t["grad_accum"],
                                        max_length=t["max_seq_len"], seed=t["seed"], eval_strategy="steps",
                                        eval_steps=t["eval_every_steps"], bf16=True, report_to=[]))
    trainer.train()
    trainer.save_model(str(out))
    preds = []
    for r in rows(cfg["data"]["test"]):
        ids = tok.apply_chat_template(to_chat(r)[:2], add_generation_prompt=True, return_tensors="pt").to(model.device)
        text = tok.decode(model.generate(ids, max_new_tokens=120, do_sample=False)[0][ids.shape[1]:], skip_special_tokens=True)
        try:
            preds.append({"id": r["id"], "prediction": json.loads(text)})
        except ValueError:
            preds.append({"id": r["id"], "prediction": None})
    (out / "test_predictions.jsonl").write_text("".join(json.dumps(p) + "\n" for p in preds))
    print(f"saved adapters and test predictions to {out}; now run model/evaluate.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
