import json
import random
from typing import Optional, List
from mutators.base import BaseMutator


class JSONMutator(BaseMutator):
    def __init__(self, seed_text: Optional[str], seed_bytes: bytes):
        super().__init__(seed_text, seed_bytes)
        self.seed_obj = None
        if self.seed_text is not None:
            try:
                self.seed_obj = json.loads(self.seed_text)
            except Exception:
                self.seed_obj = None

    def mutate(self, base: bytes) -> bytes:
        if self.seed_obj is None:
            return self.mutate_bytes(base)
        data = dict(self.seed_obj)
        choice = random.choice(["add", "modify", "nest", "overflow"])
        if choice == "add":
            data[str(random.randint(1000, 2000))] = random.choice(["val", 123, True, None])
        elif choice == "modify" and data:
            key = random.choice(list(data.keys()))
            data[key] = random.choice(["", 10 ** random.randint(5, 20), None])
        elif choice == "nest":
            depth = random.randint(2, 10)
            d = data
            for _ in range(depth):
                d = {str(random.randint(0, 100)): d}
            data = d
        elif choice == "overflow":
            data[str(random.randint(2001, 3000))] = int("9" * random.randint(20, 1000))
        s = json.dumps(data)
        return s.encode('utf-8', errors='ignore')

    def deterministic_inputs(self) -> list[bytes]:
        outs: list[bytes] = []
        base_obj = self.seed_obj if isinstance(self.seed_obj, dict) else {}
        det1 = dict(base_obj)
        for i in range(100):
            det1[f"k{i}"] = i
        outs.append(json.dumps(det1).encode('utf-8', errors='ignore'))
        d = base_obj
        for i in range(20):
            d = {f"n{i}": d}
        outs.append(json.dumps(d).encode('utf-8', errors='ignore'))
        det2 = dict(base_obj)
        det2["big"] = int("9" * 200)
        outs.append(json.dumps(det2).encode('utf-8', errors='ignore'))
        return outs
