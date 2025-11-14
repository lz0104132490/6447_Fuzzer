import csv
import io
import random
import re
from typing import Optional, List, Union, Any
from utils import is_numeric
from mutators.base import BaseMutator


class CSVMutator(BaseMutator):
    MAX_ROW_LENGTH = 1000
    MAX_FIELD_LENGTH = 10000
    DELIMITER = ','

    def __init__(self, seed_text: Optional[str], seed_bytes: bytes):
        super().__init__(seed_text, seed_bytes)
        self.header = ""
        self.rows: List[List[str]] = []
        self.parsed_header: List[str] = []
        self.parsed_rows: List[List[str]] = []
        self._writer_kwargs: dict[str, Any] = {}
        self._setup_parsed_data()
        self._setup_writer_configs()

    def _setup_parsed_data(self) -> None:
        if self.seed_text:
            self._parse_csv()
            self._validate_csv_structure()

    def _setup_writer_configs(self) -> None:
        self._writer_kwargs = {
            'delimiter': ',',
            'quotechar': '"',
            'quoting': csv.QUOTE_MINIMAL,
            'escapechar': '\\',
            'doublequote': False,
        }

    def _parse_csv(self) -> None:
        try:
            reader = csv.reader(io.StringIO(self.seed_text))
            self.parsed_rows = list(reader)
            if self.parsed_rows:
                self.parsed_header = self.parsed_rows[0]
                self.parsed_rows = self.parsed_rows[1:]
                lines = self.seed_text.splitlines()
                if lines:
                    self.header = lines[0]
                    self.rows = [line.split(',') for line in lines[1:]]
        except Exception:
            lines = self.seed_text.splitlines()
            if lines:
                self.header = lines[0]
                self.rows = [line.split(',') for line in lines[1:]]
                self.parsed_header = self.header.split(',')
                self.parsed_rows = self.rows

    def _validate_csv_structure(self) -> bool:
        if self.parsed_header and not isinstance(self.parsed_header, list):
            try:
                self.parsed_header = list(self.parsed_header)
            except Exception:
                self.parsed_header = []
        trimmed_rows: List[List[str]] = []
        for row in self.parsed_rows:
            if not isinstance(row, list):
                try:
                    row = list(row)
                except Exception:
                    row = []
            if len(row) > self.MAX_ROW_LENGTH:
                row = row[: self.MAX_ROW_LENGTH]
            row = [f[: self.MAX_FIELD_LENGTH] if isinstance(f, str) else str(f) for f in row]
            trimmed_rows.append(row)
        self.parsed_rows = trimmed_rows
        return True

    def _detect_delimiter(self) -> str:
        try:
            sample = (self.seed_text or '')[:4096]
            if not sample:
                return ','
            dialect = csv.Sniffer().sniff(sample, delimiters=[',', ';', '\t', '|', ':'])
            return getattr(dialect, 'delimiter', ',') or ','
        except Exception:
            return ','

    def _get_csv_writer(self, output: io.StringIO) -> csv.writer:
        if getattr(self, "_writer_kwargs", None):
            return csv.writer(output, **self._writer_kwargs)
        return csv.writer(
            output,
            delimiter=self._detect_delimiter(),
            quotechar='"',
            quoting=csv.QUOTE_MINIMAL,
            escapechar='\\',
            doublequote=False,
        )

    def _write_csv(self, writer: csv.writer, header: Optional[List[str]] = None,
                   rows: Optional[Union[List[List[str]], List[str]]] = None) -> None:
        if header is not None:
            writer.writerow(header)
        if rows is not None and len(rows) > 0:
            writer.writerows(rows if isinstance(rows[0], (list, tuple)) else [rows])

    def _mutate_field(self, field: str, field_index: int) -> str:
        if random.random() > 0.3:
            return field
        mutations: List[str] = []
        if is_numeric(field):
            mutations.extend(self._get_numeric_mutations(field))
        mutations.extend(self._get_string_mutations(field))
        mutations.extend([
            field * 2,
            field + field[::-1],
            field.upper(),
            field.lower(),
            field.strip(),
            field.replace(" ", ""),
        ])
        return random.choice(mutations) if mutations else field

    # Seed-based deterministic mutations
    def _det_double_commas(self) -> List[bytes]:
        if not self.seed_text:
            return []
        delim = self._detect_delimiter()
        return [self.seed_text.replace(delim, delim * 2).encode('utf-8', errors='replace')]

    def _det_remove_first_comma(self) -> List[bytes]:
        if not self.seed_text:
            return []
        delim = self._detect_delimiter()
        return [self.seed_text.replace(delim, '', 1).encode('utf-8', errors='replace')]

    def _det_trailing_comma_each_line(self) -> List[bytes]:
        if not self.seed_text:
            return []
        delim = self._detect_delimiter()
        lines = self.seed_text.splitlines()
        lines_tc = [ln + delim if ln.strip() != '' else ln for ln in lines]
        return ['\n'.join(lines_tc).encode('utf-8', errors='replace')]

    def _det_mixed_line_endings(self) -> List[bytes]:
        if not self.seed_text:
            return []
        le_variants = ['\n', '\r', '\r\n']
        mixed: List[str] = []
        for i, ln in enumerate(self.seed_text.splitlines()):
            mixed.append(ln + le_variants[i % len(le_variants)])
        return [''.join(mixed).encode('utf-8', errors='replace')]

    def _det_leading_trailing_blank_lines(self) -> List[bytes]:
        return [] if not self.seed_text else [('\n\n' + self.seed_text + '\n\n').encode('utf-8', errors='replace')]

    def _det_duplicate_header(self) -> List[bytes]:
        if not self.seed_text:
            return []
        lines = self.seed_text.splitlines()
        if not lines:
            return []
        header = lines[0]
        rest = '\n'.join(lines[1:]) if len(lines) > 1 else ''
        dup = header + '\n' + header + ('\n' + rest if rest else '')
        return [dup.encode('utf-8', errors='replace')]

    def _det_truncate_mid_file(self) -> List[bytes]:
        if not self.seed_text:
            return []
        mid = len(self.seed_text) // 2
        return [self.seed_text[:mid].encode('utf-8', errors='replace')]

    def _det_unmatched_quote(self) -> List[bytes]:
        if not self.seed_text:
            return []
        s = self.seed_text
        if '"' in s:
            i = s.find('"')
            return [(s[:i] + '"' + s[i:]).encode('utf-8', errors='replace')]
        parts = s.splitlines()
        if parts:
            parts[0] = parts[0] + ',"unclosed'
            return ['\n'.join(parts).encode('utf-8', errors='replace')]
        return []

    def _det_newline_in_quoted_field(self) -> List[bytes]:
        if not self.seed_text:
            return []
        m = re.search(r'"([^"]*)"', self.seed_text)
        if not m:
            return []
        content = m.group(1)
        new_content = content + '\nNEWLINE_IN_FIELD'
        mutated = self.seed_text[:m.start()] + '"' + new_content + '"' + self.seed_text[m.end():]
        return [mutated.encode('utf-8', errors='replace')]

    def _det_very_long_first_cell(self) -> List[bytes]:
        if not self.seed_text:
            return []
        lines = self.seed_text.splitlines()
        if not lines:
            return []
        cols = lines[0].split(',')
        if not cols:
            return []
        huge = 'A' * (1024 * 512)
        cols[0] = '"' + huge + '"'
        mutated_header = ','.join(cols)
        rest = '\n'.join(lines[1:]) if len(lines) > 1 else ''
        return [(mutated_header + ('\n' + rest if rest else '')).encode('utf-8', errors='replace')]

    def _det_utf8_bom(self) -> List[bytes]:
        return [] if not self.seed_text else [('\ufeff' + self.seed_text).encode('utf-8', errors='replace')]

    def _det_csv_formula_in_first_data_row(self) -> List[bytes]:
        if not self.seed_text:
            return []
        lines = self.seed_text.splitlines()
        if len(lines) < 2:
            return []
        data_parts = lines[1].split(',')
        data_parts[0] = '="=CMD"'
        mutated = lines[0] + '\n' + ','.join(data_parts) + ('\n' + '\n'.join(lines[2:]) if len(lines) > 2 else '')
        return [mutated.encode('utf-8', errors='replace')]

    def _det_extra_header_no_data(self) -> List[bytes]:
        if not self.seed_text:
            return []
        lines = self.seed_text.splitlines()
        if not lines:
            return []
        header_cols = lines[0].split(',')
        header_cols.append('extra_col')
        new_header = ','.join(header_cols)
        mutated = new_header + '\n' + '\n'.join(lines[1:])
        return [mutated.encode('utf-8', errors='replace')]

    def _det_extra_header_100_cols(self) -> List[bytes]:
        if not self.seed_text:
            return []
        lines = self.seed_text.splitlines()
        if not lines:
            return []
        header_cols = lines[0].split(',')
        header_cols_extended = header_cols + [f'extra_col_{i}' for i in range(10000)]
        new_header_ext = ','.join(header_cols_extended)
        mutated_ext = new_header_ext + '\n' + '\n'.join(lines[1:])
        return [mutated_ext.encode('utf-8', errors='replace')]

    def _det_extra_first_line_100_col(self) -> List[bytes]:
        if not self.seed_text:
            return []
        lines = self.seed_text.splitlines()
        if len(lines) < 2:
            return []
        delim = self._detect_delimiter()
        extended = lines[1] + delim + ''.join([f"extra_val_{i}" for i in range(100)]) + '\n'
        mutated = (
            lines[0]
            + '\n'
            + extended * 100  # or 1, depending on your intention
            + ('\n'.join(lines[2:]) if len(lines) > 2 else '')
        )
        return [mutated.encode('utf-8', errors='replace')]

    def _det_empty_file_cases(self) -> List[bytes]:
        cases = [b""]
        cases.append(b"id,name")
        cases.append(b"id,name\n1,Alice")
        cases.append(b"id,name\n,")

        return cases

    def _det_header_only_cases(self) -> List[bytes]:
        if not self.seed_text:
            return []

        lines = self.seed_text.splitlines()
        if not lines:
            return []

        header = lines[0]
        cols = header.split(',')

        # If header is weird or empty, bail out
        if not any(c.strip() for c in cols):
            return []

        # Case 1: header only (as-is) – some parsers treat this specially
        cases: List[bytes] = [header.encode('utf-8', errors='replace')]

        # Case 2: header + empty data row with same number of columns
        empty_row = ','.join(['' for _ in cols])
        cases.append(f"{header}\n{empty_row}".encode('utf-8', errors='replace'))

        # Case 3: header + shorter row (one fewer column)
        if len(cols) > 1:
            shorter_row = ','.join(['' for _ in cols[:-1]])
            cases.append(f"{header}\n{shorter_row}".encode('utf-8', errors='replace'))

        return cases

    def _det_invalid_byte_sequence(self) -> List[bytes]:
        if not self.seed_text:
            return []
        try:
            mutated = self.seed_text + bytes([0xff, 0xfe]).decode('latin1')
            return [mutated.encode('utf-8', errors='replace')]
        except Exception:
            return []

    def _det_collapsed_single_line(self) -> List[bytes]:
        return [] if not self.seed_text else [self.seed_text.replace('\n', ' ').encode('utf-8', errors='replace')]

    def _generate_basic_cases(self) -> List[bytes]:
        outs: List[bytes] = []
        outs.extend(self._det_empty_file_cases())
        outs.extend(self._det_header_only_cases())
        outs.extend(self._det_double_commas())
        outs.extend(self._det_remove_first_comma())
        outs.extend(self._det_trailing_comma_each_line())
        outs.extend(self._det_mixed_line_endings())
        outs.extend(self._det_leading_trailing_blank_lines())
        outs.extend(self._det_truncate_mid_file())
        outs.extend(self._det_unmatched_quote())
        outs.extend(self._det_newline_in_quoted_field())
        outs.extend(self._det_collapsed_single_line())
        return outs

    def _generate_header_mutations(self) -> List[bytes]:
        outs: List[bytes] = []
        outs.extend(self._det_duplicate_header())
        outs.extend(self._det_extra_header_no_data())
        outs.extend(self._det_extra_header_100_cols())
        outs.extend(self._det_very_long_first_cell())
        return outs

    def _generate_row_mutations(self) -> List[bytes]:
        outs: List[bytes] = []
        outs.extend(self._det_csv_formula_in_first_data_row())
        outs.extend(self._det_extra_first_line_100_col())
        return outs

    def _generate_special_cases(self) -> List[bytes]:
        outs: List[bytes] = []
        outs.extend(self._det_utf8_bom())
        outs.extend(self._det_invalid_byte_sequence())
        return outs

    def _generate_random_cases(self) -> List[bytes]:
        if not self.seed_text:
            return []
        rng = random.Random(hash(self.seed_text))
        lines = self.seed_text.splitlines()
        if not lines:
            return []
        data = lines[:]
        rng.shuffle(data)
        return ['\n'.join(data).encode('utf-8', errors='replace')]

    def deterministic_inputs(self) -> List[bytes]:
        test_cases: List[bytes] = []
        test_cases.extend(self._generate_basic_cases())
        test_cases.extend(self._generate_header_mutations())
        test_cases.extend(self._generate_row_mutations())
        test_cases.extend(self._generate_special_cases())
        test_cases.extend(self._generate_random_cases())
        return test_cases

    def mutate(self, base: bytes) -> bytes:
        if not self.parsed_header or not self.parsed_rows:
            if self.seed_text is not None:
                mg = self._mutate_generic_text_once(self.seed_text)
                return mg.encode('utf-8', errors='ignore')
            return self.mutate_bytes(base)
        row_idx = random.randint(0, len(self.parsed_rows) - 1)
        row = self.parsed_rows[row_idx].copy()
        for i in range(len(row)):
            if random.random() < 0.7:
                row[i] = self._mutate_field(row[i], i)
        if random.random() < 0.3:
            if random.choice([True, False]) and len(row) > 1:
                row.pop(random.randint(0, len(row) - 1))
            else:
                row.insert(random.randint(0, len(row)), "EXTRA_FIELD")
        output = io.StringIO()
        writer = self._get_csv_writer(output)
        try:
            if self.parsed_header:
                writer.writerow(self.parsed_header)
            writer.writerow(row)
            if random.random() < 0.2:
                for _ in range(random.randint(1, 3)):
                    writer.writerow([f"EXTRA_{i}_{random.randint(1, 1000)}" for i in range(random.randint(1, max(1, len(self.parsed_header) * 2)))])
            return output.getvalue().encode('utf-8', errors='ignore')
        except Exception as e:
            print(f"[!] CSV mutation failed: {e}")
            return self.mutate_bytes(base)
