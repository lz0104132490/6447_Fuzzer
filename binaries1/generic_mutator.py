# mutators/generic_mutator.py
import random
import copy

class GenericMutator:
    def __init__(self, seed_data: bytes):
        self.seed = seed_data
        if len(self.seed) == 0:
            self.seed = b"A"  # ensure non-empty seed for mutation

    def mutate(self) -> bytes:
        data = bytearray(self.seed)  # work on a mutable copy
        choice = random.choice(["bit_flip", "random_byte", "reverse_chunk", "insert_null", "extend"])
        if choice == "bit_flip":
            # Flip a single random bit in the data
            idx = random.randrange(len(data))
            bit = 1 << random.randrange(8)
            data[idx] ^= bit
        elif choice == "random_byte":
            # Replace a random byte with a random value
            idx = random.randrange(len(data))
            data[idx] = random.randrange(256)
        elif choice == "reverse_chunk":
            if len(data) > 1:
                start = random.randrange(len(data))
                end = random.randrange(start, len(data))
                chunk = data[start:end]
                chunk.reverse()
                data[start:end] = chunk
        elif choice == "insert_null":
            # Insert one or more null bytes at a random position
            pos = random.randrange(len(data)+1)
            num_nulls = random.randint(1, 4)
            data[pos:pos] = b"\x00" * num_nulls
        elif choice == "extend":
            # Concatenate the data with a duplicate or random bytes to increase length
            extra = data if random.random() < 0.5 else bytearray(random.randrange(256) for _ in range(len(data)))
            data = data + extra
        return bytes(data)
