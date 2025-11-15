import json
import random
import copy
from typing import Optional, List
from mutators.base import BaseMutator

MAX_DEPTH = 5
MAX_SIZE = 10000

class JSONMutator(BaseMutator):
    def __init__(self, seed_text: Optional[str], seed_bytes: bytes):
        super().__init__(seed_text, seed_bytes)
        self.seed_obj = None
        if self.seed_text is not None:
            try:
                self.seed_obj = json.loads(self.seed_text)
            except Exception:
                self.seed_obj = None
        # Register deterministic generators
        self._deterministic_generators = [
            self._det_classic_sequential_dict,
            self._det_deep_nest,
            self._det_large_number,
            self._det_stress_list,
            self._det_malformed_explicitly,
            self._det_edge_keys_and_removals
            self._det_overflow_bytes(self.seed_bytes)
            self._det_empty_file()
        ]

    def mutate(self, base: bytes) -> bytes:
        if self.seed_obj is None:
            return self.mutate_bytes(base)

        # Always use deepcopy for isolation
        data = copy.deepcopy(self.seed_obj)

        # Somewhat randomly emit malformed JSON (20% chance)
        if random.random() < 0.2:
            return self._malformed_json(data)

        # Structural mutation
        data = self._mutate_structure(data, depth=0)
        try:
            s = json.dumps(data)
        except Exception:
            # Defensive fallback; emit a basic broken string
            s = '{broken:}'
        return s.encode('utf-8', errors='ignore')

    def _mutate_structure(self, obj, depth=0):
        if depth > MAX_DEPTH:
            return obj
        if isinstance(obj, dict):
            obj = copy.deepcopy(obj)
            actions = ["add", "modify", "delete", "swap", "type_change"]
            # Do at least one mutation, possibly more
            for _ in range(random.randint(1, 3)):
                choice = random.choice(actions)
                keys = list(obj.keys())
                if choice == "add":
                    obj[self._random_unicode_key()] = self._random_value(depth + 1)
                elif choice == "modify" and keys:
                    key = random.choice(keys)
                    obj[key] = self._random_value(depth + 1)
                elif choice == "delete" and keys:
                    key = random.choice(keys)
                    del obj[key]
                elif choice == "swap" and len(keys) > 1:
                    k1, k2 = random.sample(keys, 2)
                    obj[k1], obj[k2] = obj[k2], obj[k1]
                elif choice == "type_change" and keys:
                    key = random.choice(keys)
                    obj[key] = self._type_flip(obj[key])
            # Possibly recurse
            for k in list(obj.keys()):
                if random.random() < 0.5:
                    obj[k] = self._mutate_structure(obj[k], depth=depth+1)
            return obj
        elif isinstance(obj, list):
            obj = list(obj)  # shallow copy fine, nested handled below
            if obj:
                actions = ["modify", "delete", "swap"]
                for _ in range(random.randint(1, 3)):
                    choice = random.choice(actions)
                    if choice == "modify":
                        idx = random.randrange(len(obj))
                        obj[idx] = self._random_value(depth + 1)
                    elif choice == "delete" and len(obj) > 1:
                        del obj[random.randrange(len(obj))]
                    elif choice == "swap" and len(obj) > 1:
                        i1, i2 = random.sample(range(len(obj)), 2)
                        obj[i1], obj[i2] = obj[i2], obj[i1]
            # recurse sometimes
            for i in range(len(obj)):
                if random.random() < 0.5:
                    obj[i] = self._mutate_structure(obj[i], depth=depth+1)
            # limit list size
            if len(obj) > MAX_SIZE:
                obj = obj[:MAX_SIZE]
            return obj
        else:
            # Basic value
            return self._random_value(depth + 1) if random.random() < 0.2 else obj

    # --- Private utility methods ---
    def _random_unicode_key(self):
        # Mix ASCII, unicode, and edge-case keys
        keys = [
            ''.join(chr(random.randint(32, 126)) for _ in range(random.randint(3, 12))),
            "\udc00",
            "𝓤𝓷𝓲𝓬𝓸𝓭𝓮",
            "key\uFFFF",
            "",
            str(random.randint(0, 1000000))
        ]
        return random.choice(keys)

    def _random_value(self, depth):
        # Values; edge numbers, odd strings, lists, dicts, bool, null, etc
        options = [
            None,
            True,
            False,
            "\n\r\t\x00\u202e",
            "壊れた",
            float('nan'),
            float('inf'),
            -float('inf'),
            10 ** random.randint(1, 100),
            "9999999999999999999999",
            [self._random_value(depth+1) for _ in range(random.randint(1, 4))] if depth < MAX_DEPTH else [],
            {self._random_unicode_key(): self._random_value(depth+1) for _ in range(random.randint(1, 3))} if depth < MAX_DEPTH else {},
            random.uniform(-1e10, 1e10),
            random.randint(-1e9, 1e9),
            "randomstr" + str(random.randint(0, 1000)) + '\\' + random.choice(["", "\n", "\u202e"]),
            "simple"
        ]
        return random.choice(options)

    def _type_flip(self, v):
        # Randomly convert v to another type
        types = [lambda: str(v), lambda: [v], lambda: {"k": v}, lambda: None, lambda: 123, lambda: "v"]
        try:
            return random.choice(types)()
        except Exception:
            return None

    def _malformed_json(self, data):
        # Dump valid, then corrupt as string
        try:
            s = json.dumps(data)
        except Exception:
            s = '{}'
        corruptions = [
            lambda s: s[:-random.randint(1, 5)],                               # Truncate
            lambda s: s + random.choice([']', ']', '"', '{', '\\', ',']),   # Incomplete
            lambda s: s.replace('{', '', 1),                                  # Missing brace
            lambda s: s.replace('"', '', random.randint(1, 3)),              # Remove quotes
            lambda s: s + '\x00\\u202e',                                    # Add control char
        ]
        s = random.choice(corruptions)(s)
        return s.encode('utf-8', errors='ignore')
    
    # --- Deterministic input generators ---
    def _det_classic_sequential_dict(self, base_obj) -> bytes:
        det1 = copy.deepcopy(base_obj)
        for i in range(100):
            det1[f"k{i}"] = i
        return json.dumps(det1).encode('utf-8', errors='ignore')

    def _det_deep_nest(self, base_obj) -> bytes:
        d = copy.deepcopy(base_obj)
        for i in range(10):
            d = {f"n{i}": d}
        return json.dumps(d).encode('utf-8', errors='ignore')

    def _det_large_number(self, base_obj) -> bytes:
        det2 = copy.deepcopy(base_obj)
        det2["big"] = int("9" * 100)
        return json.dumps(det2).encode('utf-8', errors='ignore')

    def _det_stress_list(self) -> bytes:
        stress_list = [self._random_value(1) for _ in range(200)]
        return json.dumps(stress_list).encode('utf-8', errors='ignore')

    def _det_malformed_explicitly(self, base_obj) -> bytes:
        return self._malformed_json(base_obj)

    def _det_edge_keys_and_removals(self, base_obj) -> bytes:
        remov = copy.deepcopy(base_obj)
        for i in list(remov.keys())[:3]:
            del remov[i]
        remov["\udc00"] = "edge"
        return json.dumps(remov).encode('utf-8', errors='ignore')

    def deterministic_inputs(self) -> list[bytes]:
        outs: list[bytes] = []
        # deterministic mutations expect to be applied to a dict
        base_obj = copy.deepcopy(self.seed_obj) if isinstance(self.seed_obj, dict) else {}
        for gen in self._deterministic_generators:
            # If the function needs base_obj, pass it; else, call with no arg
            if 'base_obj' in gen.__code__.co_varnames:
                outs.append(gen(base_obj))
            else:
                outs.append(gen())
        return outs
