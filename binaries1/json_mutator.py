# mutators/json_mutator.py
import json
import random
import string
import copy

class JSONMutator:
    def __init__(self, seed_data: bytes):
        self.seed_text = seed_data.decode('utf-8', errors='ignore')
        # Try to parse JSON for structured mutations
        try:
            self.seed_json = json.loads(self.seed_text)
        except Exception:
            self.seed_json = None  # If parsing fails, we'll fall back to text-based mutation

    def mutate(self) -> bytes:
        # If parsed JSON is available, do structured mutation
        if self.seed_json is not None:
            data = self.seed_json
            mutated = copy.deepcopy(data)
            # Random choice of mutation strategy
            choice = random.choice(["add_key", "nest", "large_value"])
            if choice == "add_key" and isinstance(mutated, dict):
                # Add a new key with a random large string value
                new_key = "FUZZKEY" + "".join(random.choices(string.ascii_letters, k=5))
                mutated[new_key] = "A" * random.randint(1000, 5000)  # large string value
            elif choice == "nest":
                # Wrap the entire JSON inside another layer of nesting
                mutated = {"nested": data}
                # Optionally repeat to increase nesting depth
                for _ in range(random.randint(1, 5)):
                    mutated = {"nested": mutated}
            elif choice == "large_value":
                # Find a place to insert a large numeric value
                # If there's a list, append a large number; otherwise add a new key with large number
                big_num = 2**31 + random.randint(0, 1000)  # number slightly above 32-bit int range
                if isinstance(mutated, list):
                    mutated.append(big_num)
                elif isinstance(mutated, dict):
                    mutated["big_number"] = big_num
            try:
                # Convert back to JSON text
                new_text = json.dumps(mutated)
                return new_text.encode('utf-8')
            except Exception:
                # If serialization fails (e.g., due to recursion depth), fall back to original text
                return self.seed_text.encode('utf-8')
        else:
            # If not a valid JSON, just do a generic text mutation
            text = self.seed_text
            # Simple text mutation: insert a random chunk of text
            insert = "{\"FUZZ\": true}"
            pos = random.randint(0, len(text))
            new_text = text[:pos] + insert + text[pos:]
            return new_text.encode('utf-8')
