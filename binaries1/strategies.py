# strategies.py
from json_mutator import JSONMutator
from csv_mutator import CSVMutator
from generic_mutator import GenericMutator

def get_mutator_class(input_type: str):
    # Map the input type string to the corresponding Mutator class
    if input_type == "JSON":
        return JSONMutator
    if input_type == "CSV":
        return CSVMutator
    # If needed, one could add an XMLMutator here if defined.
    # For any other types (binary formats or plain text), use GenericMutator
    return GenericMutator
