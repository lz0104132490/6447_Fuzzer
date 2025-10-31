import os
import json
import csv
import random
import io
import copy
import subprocess
import time
import string

# ------------ JSON helpers (针对 json2 也有效) ------------

def _rand_long_string(min_len=512, max_len=2048):
    length = random.randint(min_len, max_len)
    pool = string.ascii_letters + string.digits + string.punctuation + " \t\n\x00"
    return "".join(random.choices(pool, k=length))

def _rand_big_int():
    digits = random.randint(12, 36)
    s = "".join(random.choices(string.digits, k=digits))
    if random.random() < 0.5:
        s = "-" + s
    try:
        return int(s)
    except Exception:
        return 10**9

def _wrap_nested(val, max_depth=3):
    depth = random.randint(1, max_depth)
    out = val
    for _ in range(depth):
        out = [out] if random.random() < 0.5 else {"k": out}
    return out

def _looks_like_numeric_key_object(obj):
    if not isinstance(obj, dict) or not obj:
        return False
    keys = list(obj.keys())
    if not all(isinstance(k, str) and k.isdigit() for k in keys):
        return False
    ints = sorted(int(k) for k in keys)
    return ints == list(range(len(keys))) and len(keys) >= 3

def _object_to_expanded_array(obj, base_len=0):
    n = len(obj) if base_len == 0 else base_len
    arr = [obj[str(i)] if str(i) in obj else None for i in range(n)]
    target = random.randint(max(64, n), max(64, n) + 192)
    while len(arr) < target:
        if random.random() < 0.5 and arr:
            v = copy.deepcopy(random.choice(arr))
            if isinstance(v, (int, float)) and random.random() < 0.5:
                v = _rand_big_int()
            elif isinstance(v, str) and random.random() < 0.5:
                v = v + _rand_long_string(32, 128)
            elif v is None or random.random() < 0.2:
                v = random.choice([None, True, False, _rand_big_int(), _rand_long_string(64, 256)])
            arr.append(v)
        else:
            arr.append(random.choice([None, True, False, _rand_big_int(), _rand_long_string(64, 256), {"x": 1}]))
    return arr

def random_value():
    return random.choice([
        None, True, False,
        0, -1, 2**31 - 1, -(2**31),
        _rand_big_int(),
        _rand_long_string(64, 256),
        "<script>", "' OR '1'='1", "%x", "%n", "\\", "\"", "\n", "\r\n", "\x00",
        {"random": random.randint(0, 10)},
        [random.randint(0, 10) for _ in range(random.randint(1, 4))]
    ])

def mutate_string(s):
    specials = ["", "AAAA", "{}", "\"", "\n", "\r\n", ",", "\x00", " " * 10, "%x", "%n"]
    options = []
    seq = random.choice(specials)
    pos = random.randrange(len(s) + 1) if s else 0
    options.append(s[:pos] + seq + s[pos:])
    if s:
        start = random.randrange(len(s))
        end = start + random.randrange(1, len(s) - start + 1)
        options.append(s[:start] + s[end:])
    options.append(s + s)
    options.append(s[::-1])
    options.append(s * 2 if len(s) < 64 else s)
    options.append(_rand_long_string(64, 256))
    rand_len = random.randint(1, 24)
    options.append("".join(chr(random.randint(32, 126)) for _ in range(rand_len)))
    return random.choice(options)

def mutate_json_structure(val, depth=0, max_depth=3):
    if depth > max_depth:
        return
    if isinstance(val, dict):
        if val and random.random() < 0.5:
            key = random.choice(list(val.keys()))
            if isinstance(val[key], (dict, list)) and random.random() < 0.6:
                mutate_json_structure(val[key], depth+1, max_depth)
            else:
                if isinstance(val[key], bool):
                    val[key] = not val[key]
                elif isinstance(val[key], (int, float)):
                    val[key] = _rand_big_int() if random.random() < 0.6 else random_value()
                elif isinstance(val[key], str):
                    val[key] = mutate_string(val[key]) if random.random() < 0.5 else _wrap_nested(val[key], max_depth - depth)
                else:
                    val[key] = random_value()
        else:
            if val and random.random() < 0.5:
                val.pop(random.choice(list(val.keys())), None)
            else:
                new_key = "key" + str(random.randint(0, 100000))
                base = random_value()
                if random.random() < 0.4:
                    base = _wrap_nested(base, max_depth - depth)
                val[new_key] = base
    elif isinstance(val, list):
        if val and random.random() < 0.5:
            idx = random.randrange(len(val))
            if isinstance(val[idx], (dict, list)) and random.random() < 0.6:
                mutate_json_structure(val[idx], depth+1, max_depth)
            else:
                if isinstance(val[idx], (int, float)) and random.random() < 0.6:
                    val[idx] = _rand_big_int()
                elif isinstance(val[idx], str) and random.random() < 0.5:
                    val[idx] = mutate_string(val[idx])
                else:
                    val[idx] = random_value()
        else:
            if val and random.random() < 0.5:
                val.pop(random.randrange(len(val)))
            else:
                elem = random.choice(val) if val else random_value()
                new_elem = copy.deepcopy(elem)
                if random.random() < 0.5:
                    new_elem = _wrap_nested(new_elem, max_depth - depth)
                val.insert(random.randrange(len(val)+1), new_elem)

def mutate_json(data):
    data_copy = copy.deepcopy(data)
    if _looks_like_numeric_key_object(data_copy):
        if random.random() < 0.6:
            try:
                arr = _object_to_expanded_array(data_copy, base_len=len(data_copy))
                return json.dumps(arr, separators=(",", ":"))
            except Exception:
                pass
        else:
            cur_n = len(data_copy)
            add_n = random.randint(8, 128)
            for i in range(cur_n, cur_n + add_n):
                v = random.choice([_rand_big_int(), _rand_long_string(64, 256), {"deep": _rand_long_string(32, 96)}, None, True, False])
                data_copy[str(i)] = v
            for _ in range(min(16, len(data_copy))):
                k = str(random.randrange(0, len(data_copy)))
                if k in data_copy and isinstance(data_copy[k], (int, float)) and random.random() < 0.6:
                    data_copy[k] = _rand_big_int()
                elif k in data_copy and isinstance(data_copy[k], str) and random.random() < 0.6:
                    data_copy[k] = data_copy[k] + _rand_long_string(32, 96)
            try:
                return json.dumps(data_copy, separators=(",", ":"))
            except Exception:
                pass
    if isinstance(data_copy, (dict, list)):
        if random.random() < 0.7:
            mutate_json_structure(data_copy, depth=0, max_depth=3)
        else:
            data_copy = _wrap_nested(data_copy, max_depth=2)
    else:
        base = random_value()
        if random.random() < 0.5:
            base = _wrap_nested(base, max_depth=2)
        data_copy = base
    try:
        return json.dumps(data_copy, separators=(",", ":"))
    except Exception:
        return json.dumps(str(data_copy))

# ------------ CSV helpers（csv1 定向命中） ------------

def _is_strict_header(header_row):
    tokens = [t.strip().lower() for t in header_row]
    return tokens and ("header" in tokens and "must" in tokens and "stay" in tokens and "intact" in tokens) and len(header_row) == 4

def _mutate_field_value(val: str, heavy=False) -> str:
    if heavy:
        # 更大但不破坏列：建议纯字母/数字，避免引起额外转义
        return "".join(random.choices(string.ascii_letters, k=random.randint(1024, 2048)))
    choice = random.choice(["long", "comma", "newline", "quote", "format", "nul", "rand"])
    if choice == "long":
        return "".join(random.choices(string.ascii_letters, k=random.randint(256, 1024)))
    if choice == "comma":
        return (val or "") + "," + "".join(random.choices("xyz", k=3))
    if choice == "newline":
        return (val or "Line") + "\n" + "Cont"
    if choice == "quote":
        return (val or "He") + ' says "Hello"'
    if choice == "format":
        return (val or "") + "%x"
    if choice == "nul":
        return (val or "") + "\x00" + "Z"
    return "".join(random.choices(string.ascii_letters+string.digits, k=random.randint(1, 16)))

def _csv1_target_rows(header, existing_rows):
    """
    构造严格 csv1 负载：
    - header 原样
    - 固定 4 列
    - 先保留原有少量行，再批量追加 64–192 行
    - 前三列为单字符小写字母，最后一列为 1–2KB 超长字母串（避免逗号/换行破坏列数）
    """
    out_rows = [header[:]]
    # 保留原有行，但修齐到 4 列
    for r in existing_rows[:8]:  # 保留最多前 8 行，避免过长
        rr = r[:4] + ([""] * (4 - len(r))) if len(r) < 4 else r[:4]
        out_rows.append(rr)

    extra = random.randint(64, 192)
    for _ in range(extra):
        a = random.choice(string.ascii_lowercase)
        b = random.choice(string.ascii_lowercase)
        c = random.choice(string.ascii_lowercase)
        big = "".join(random.choices(string.ascii_letters, k=random.randint(1024, 2048)))
        out_rows.append([a, b, c, big])
    return out_rows

def mutate_csv(rows):
    if not rows:
        return "header,must,stay,intact\nx,y,z,w\n"
    header = rows[0][:]
    data_rows = [r[:] for r in rows[1:]]
    strict = _is_strict_header(header)

    if strict:
        # 80% 走专项构造，20% 做温和细胞级变异
        if random.random() < 0.8:
            rows_built = _csv1_target_rows(header, data_rows)
            output = io.StringIO()
            writer = csv.writer(output, lineterminator="\n")
            for r in rows_built:
                writer.writerow([str(x) for x in r])
            return output.getvalue()
        else:
            # 温和：不改列数/不动 header，适度放大最后一列
            col_cnt = 4
            for i, row in enumerate(data_rows):
                if len(row) < col_cnt:
                    row.extend([""] * (col_cnt - len(row)))
                elif len(row) > col_cnt:
                    row[:] = row[:col_cnt]
                idx = col_cnt - 1
                row[idx] = _mutate_field_value(str(row[idx]), heavy=(random.random() < 0.6))
            output = io.StringIO()
            writer = csv.writer(output, lineterminator="\n")
            writer.writerow(header)
            for r in data_rows:
                writer.writerow([str(x) for x in r])
            return output.getvalue()

    # 非严格模式延续上版多样化策略
    op = random.choices(
        ["mutate_cells", "extend_row", "duplicate_row", "delete_row", "duplicate_col", "delete_col"],
        weights=[35, 25, 12, 10, 10, 8],
        k=1
    )[0]
    max_rows = min(256, len(data_rows) + 64)
    max_cols = min(64, max((len(r) for r in data_rows), default=len(header)) + 8)

    if op == "mutate_cells" and data_rows:
        for _ in range(random.randint(1, max(1, len(data_rows)//2))):
            r = random.choice(data_rows)
            if not r:
                continue
            c_idx = random.randrange(len(r))
            r[c_idx] = _mutate_field_value(str(r[c_idx]), heavy=(random.random() < 0.3))
    elif op == "extend_row" and data_rows:
        for _ in range(random.randint(1, 3)):
            r = random.choice(data_rows)
            if len(r) < max_cols:
                for __ in range(random.randint(1, 3)):
                    r.append(_mutate_field_value("", heavy=(random.random() < 0.4)))
    elif op == "duplicate_row" and data_rows and len(data_rows) < max_rows:
        base = random.choice(data_rows)
        dup = base[:]
        if random.random() < 0.5 and len(dup) < max_cols:
            for __ in range(random.randint(1, 2)):
                dup.append(_mutate_field_value("", heavy=(random.random() < 0.5)))
        data_rows.insert(random.randrange(len(data_rows)+1), dup)
    elif op == "delete_row" and len(data_rows) > 1:
        data_rows.pop(random.randrange(len(data_rows)))
    elif op == "duplicate_col" and data_rows:
        col_count = max((len(r) for r in data_rows), default=len(header))
        if col_count > 0 and col_count < max_cols:
            c = random.randrange(col_count)
            for r in data_rows:
                v = r[c] if c < len(r) else ""
                r.insert(c+1, v)
            if random.random() < 0.2 and len(header) >= c+1:
                header.insert(c+1, header[c] + "_dup")
    elif op == "delete_col" and data_rows:
        col_count = max((len(r) for r in data_rows), default=len(header))
        if col_count > 1:
            c = random.randrange(col_count)
            for r in data_rows:
                if c < len(r):
                    r.pop(c)
            if random.random() < 0.2 and len(header) > c:
                header.pop(c)

    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(header)
    for row in data_rows:
        writer.writerow([str(x) for x in row])
    return output.getvalue()

# ------------ Byte-level mutation ------------

def mutate_bytes(data_bytes):
    b = bytearray(data_bytes)
    if len(b) == 0:
        b.append(random.randrange(256))
        return bytes(b)
    mut_type = random.choice(["bitflip", "insert", "delete"])
    if mut_type == "bitflip":
        idx = random.randrange(len(b))
        bit = 1 << random.randrange(8)
        b[idx] ^= bit
    elif mut_type == "insert" and len(b) < 65536:
        idx = random.randrange(len(b) + 1)
        b.insert(idx, random.randrange(256))
    elif mut_type == "delete" and len(b) > 1:
        idx = random.randrange(len(b))
        b.pop(idx)
    return bytes(b)

# ------------ Harness (60s/目标不变) ------------

def main():
    os.makedirs("/fuzzer_output", exist_ok=True)
    if not os.path.isdir("/binaries"):
        print("No /binaries directory found.")
        return

    for bin_file in os.listdir("/binaries"):
        bin_path = os.path.join("/binaries", bin_file)
        if not os.path.isfile(bin_path) or not os.access(bin_path, os.X_OK):
            continue

        seed_path = os.path.join("/example_inputs", bin_file + ".txt")
        if not os.path.isfile(seed_path):
            print(f"No seed input found for {bin_file}, skipping.")
            continue

        with open(seed_path, 'r', encoding='utf-8', errors='ignore') as f:
            seed_content = f.read()

        is_json = False
        seed_json = None
        seed_csv_rows = None
        try:
            seed_json = json.loads(seed_content)
            is_json = True
        except Exception:
            try:
                seed_csv_rows = list(csv.reader(io.StringIO(seed_content)))
                if seed_csv_rows is None:
                    seed_csv_rows = []
            except Exception:
                seed_csv_rows = []

        format_type = "JSON" if is_json else "CSV"
        print(f"[*] Fuzzing {bin_file} (format: {format_type}) for 60 seconds.")
        start_time = time.time()
        crashes = 0
        seen_hashes = set()

        while time.time() - start_time < 60:
            if is_json:
                if random.random() < 0.2:
                    mutated_bytes = mutate_bytes(seed_content.encode('utf-8', errors='ignore'))
                else:
                    mutated_text = mutate_json(seed_json)
                    mb = mutated_text.encode('utf-8', errors='ignore')
                    if random.random() < 0.1:
                        mb = mutate_bytes(mb)
                    mutated_bytes = mb
            else:
                if random.random() < 0.2:
                    mutated_bytes = mutate_bytes(seed_content.encode('utf-8', errors='ignore'))
                else:
                    mutated_text = mutate_csv(seed_csv_rows)
                    mb = mutated_text.encode('utf-8', errors='ignore')
                    if random.random() < 0.1:
                        mb = mutate_bytes(mb)
                    mutated_bytes = mb

            h = hash(mutated_bytes)
            if h in seen_hashes:
                continue
            seen_hashes.add(h)

            try:
                result = subprocess.run(
                    [bin_path],
                    input=mutated_bytes,
                    capture_output=True,
                    timeout=1,
                    check=False
                )
            except subprocess.TimeoutExpired:
                continue

            rc = result.returncode
            crashed = False
            if rc is not None:
                if rc < 0 and (-rc in (6, 11)):
                    crashed = True
                elif rc in (134, 139):
                    crashed = True

            if crashed:
                crashes += 1
                crash_file = os.path.join("/fuzzer_output", f"bad_{bin_file}.txt")
                try:
                    mutated_str = mutated_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    mutated_str = mutated_bytes.decode('latin-1', errors='ignore')
                with open(crash_file, ("a" if os.path.exists(crash_file) else "w"),
                          encoding='utf-8', errors='ignore') as cf:
                    cf.write(mutated_str + "\n\n")
                print(f"[!] Crash detected in {bin_file} (rc={rc}), saved to {crash_file}")

        print(f"[*] Finished fuzzing {bin_file}. Total crashes: {crashes}\n")

if __name__ == "__main__":
    main()
