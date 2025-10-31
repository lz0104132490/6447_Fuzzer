# mutators/csv_mutator.py
import random
import string

class CSVMutator:
    def __init__(self, seed_data: bytes):
        # Store the original lines
        self.lines = seed_data.decode('utf-8', errors='ignore').splitlines()
        if not self.lines:
            self.lines = [""]  # ensure at least one line

    def mutate(self) -> bytes:
        lines = self.lines[:]  # shallow copy of lines list
        choice = random.choice(["add_row", "add_col", "mutate_field"])
        if choice == "add_row":
            # Create a new random row (with random number of fields)
            num_fields = random.randint(1, max(1, lines[0].count(',')+1))
            new_fields = []
            for _ in range(num_fields):
                # random short string or number for each field
                field = "".join(random.choices(string.ascii_letters, k=4))
                new_fields.append(field)
            new_row = ",".join(new_fields)
            lines.append(new_row)
        elif choice == "add_col":
            # Append an extra field to each line (making CSV ragged/inconsistent)
            for i, line in enumerate(lines):
                lines[i] = line + "," + "".join(random.choices(string.ascii_letters, k=4))
        else:  # mutate_field
            # Pick a random line and a random field in it to mutate
            line_idx = random.randrange(len(lines))
            fields = lines[line_idx].split(",")
            if fields:
                field_idx = random.randrange(len(fields))
                mutation_type = random.choice(["format", "long"])
                if mutation_type == "format":
                    # Inject a format specifier into the field
                    fields[field_idx] = fields[field_idx] + "%x"  # e.g., add a %x at end
                else:  # "long"
                    # Replace field with a long string
                    fields[field_idx] = "A" * random.randint(1000, 5000)
                lines[line_idx] = ",".join(fields)
        # Join the lines back together
        new_text = "\n".join(lines)
        return new_text.encode('utf-8')
