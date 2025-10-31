import subprocess
import random
import time
import os
import json
import sys
from collections import defaultdict # 导入 defaultdict 用于数据收集

# --- Configuration and Constants ---
TIMEOUT_PER_BINARY = 60  # seconds
MAX_MUTATIONS_PER_CYCLE = 200 # How many times to mutate the current test case before moving on

# Common "magic" and edge case values for mutation
MAGIC_VALUES = [
    b'\x00', b'\xff' * 4, b'\xff' * 8,  # Null bytes, max integers
    b'AAAA' * 100, b'BBBB' * 100,      # Long, repeating strings
    b'%n%n%n%n', b'%s%s%s%s',          # Format string specifiers
    b'\x7f\xff\xff\xff', b'\x80\x00\x00\x00', # Signed integer boundaries
    b'\x01\x00\x00\x00\x00\x00\x00\x00' * 100 # Long stream of small values
]

class Fuzzer:
    """
    A Black Box Fuzzer implementation combining generational and mutational techniques.
    """
    def __init__(self, target_binary_path, seed_input_path, timeout=TIMEOUT_PER_BINARY):
        # 目标二进制文件路径
        self.target = target_binary_path
        self.timeout = timeout
        # 加载种子文件
        self.seed_data = self.load_seed(seed_input_path)
        self.input_format = self.guess_format(self.seed_data)
        
        # *** 关键修改 1: 用于存储崩溃输入的内存列表 ***
        self.crashing_inputs = [] 
        self.crashes = [] 
        
        self.total_tests = 0
        self.start_time = 0

        print(f"[*] Initializing fuzzer for: {os.path.basename(self.target)}")
        print(f"[*] Target binary path: {self.target}")
        print(f"[*] Guessed input format: {self.input_format}")
        print(f"[*] Seed input size: {len(self.seed_data)} bytes")

    def load_seed(self, file_path):
        """加载初始的有效输入文件。"""
        # (略去文件检查逻辑以保持简洁，相信路径已修正)
        try:
            with open(file_path, 'rb') as f:
                return f.read()
        except FileNotFoundError:
            err_msg = f"[!] FATAL ERROR: Seed file not found at expected path: {file_path}"
            print(err_msg)
            sys.exit(1)
        # (其他异常处理...略)
        
    def guess_format(self, data):
        """简单的启发式方法来猜测输入格式。"""
        # (保留原有格式猜测逻辑)
        try:
            data_str = data.decode('utf-8', errors='ignore').strip()
            json.loads(data_str)
            return 'JSON'
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass 
        
        if b'\n' in data or b',' in data:
            if data.startswith(b'\xff\xd8\xff') or data.startswith(b'%PDF-') or data.startswith(b'\x7fELF'):
                return 'BINARY'
            return 'PLAINTEXT/CSV'
        
        return 'BINARY'

    def _execute_target(self, input_data):
        """通过 stdin 执行目标二进制文件并提供输入数据。"""
        self.total_tests += 1
        
        try:
            result = subprocess.run(
                [self.target], 
                input=input_data,
                capture_output=True,
                timeout=2,
                check=False
            )
            
            if result.returncode != 0:
                return True # 发现崩溃
        
        except FileNotFoundError:
            print(f"[!] Target binary not found: {self.target}. Ensure it is executable.")
            return False
            
        except subprocess.TimeoutExpired:
            print("[!!!] Target timed out.")
            return True 
        except Exception as e:
            print(f"[!] An unexpected error occurred during execution: {e}")
            return False
            
        return False # 没有发现崩溃
        
    
    def _mutate_random_byte(self, data):
        # (保留突变器逻辑)
        if not data: return data
        data_list = list(data)
        idx = random.randint(0, len(data_list) - 1)
        data_list[idx] = random.randint(0, 255)
        return bytes(data_list)

    def _mutate_insert_delete(self, data):
        # (保留突变器逻辑)
        if not data: return data
        data_list = list(data)
        action = random.choice(['insert', 'delete'])
        if action == 'insert':
            idx = random.randint(0, len(data_list))
            insert_val = random.choice(MAGIC_VALUES) + os.urandom(random.randint(1, 16))
            data_list[idx:idx] = list(insert_val)
        elif action == 'delete' and len(data_list) > 1:
            start = random.randint(0, len(data_list) - 1)
            end = random.randint(start + 1, len(data_list))
            del data_list[start:end]
        return bytes(data_list)

    def _mutate_magic_values(self, data):
        # (保留突变器逻辑)
        if not data: return data
        data_list = list(data)
        magic = random.choice(MAGIC_VALUES)
        if len(data) > len(magic):
            start = random.randint(0, len(data) - len(magic))
            end = start + len(magic)
            data_list[start:end] = list(magic)
        return bytes(data_list)

    def _mutate_json_aware(self, data):
        # (保留突变器逻辑)
        try:
            data_str = data.decode('utf-8')
            parsed_json = json.loads(data_str)
            if not isinstance(parsed_json, dict): return data

            keys = list(parsed_json.keys())
            if not keys: return data
            key_to_mutate = random.choice(keys)
            old_value = parsed_json[key_to_mutate]

            if isinstance(old_value, int):
                new_value = random.choice([0, -1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, old_value + 1, old_value - 1])
            elif isinstance(old_value, str):
                new_value = random.choice([
                    "A" * (len(old_value) + 1), 
                    "A" * 1024,
                    "%s" * 10,
                    old_value + "\\n"
                ])
            elif isinstance(old_value, list):
                new_value = random.choice([[], [1]*1024])
            else:
                new_value = old_value

            parsed_json[key_to_mutate] = new_value
            fuzzed_str = json.dumps(parsed_json)
            
            if random.random() < 0.3:
                fuzzed_str = fuzzed_str.replace('"', random.choice(["'", '']), 1)
                fuzzed_str = fuzzed_str.replace(':', random.choice(['::', ':::', ' ']), 1)
                fuzzed_str = fuzzed_str.replace('{', '[', 1)
                
            return fuzzed_str.encode('utf-8')

        except Exception:
            return self._mutate_random_byte(data)
    
    def _simple_generators(self):
        # (保留生成器逻辑)
        yield b''
        yield b'A' * (1024 * 1024 * 4) 
        yield b'\x00' * 4096 
        yield b'\xff' * 4096 
        yield b'\r\n' * 2048
        yield b'%s' * 500
        yield b'2147483647\n'
        yield b'4294967295\n'
        yield b'9223372036854775807\n'

    
    def run(self):
        """在时间限制内启动模糊测试过程。"""
        self.start_time = time.time()
        end_time = self.start_time + self.timeout
        
        print(f"\n[+] Starting fuzzing campaign for {os.path.basename(self.target)}...")

        # (省略 fuzzing 循环逻辑...)
        
        # Phase 1: Generational Fuzzing
        print("[*] Phase 1: Running simple generators...")
        for input_data in self._simple_generators():
            if time.time() >= end_time:
                print("[!] Timeout reached during generational fuzzing.")
                # *** 关键修改 2: 返回崩溃数据 ***
                return self.crashes, self.crashing_inputs
            
            self._check_and_report(input_data)

        # Phase 2: Mutational Fuzzing
        print("[*] Phase 2: Starting mutational fuzzing...")
        mutators = [self._mutate_random_byte, self._mutate_insert_delete, self._mutate_magic_values]
        if self.input_format == 'JSON':
            mutators.append(self._mutate_json_aware)
        
        fuzz_iterations = 0
        while time.time() < end_time:
            mutator = random.choice(mutators)
            fuzzed_data = mutator(self.seed_data)
            
            for _ in range(random.randint(1, 5)):
                 fuzzed_data = self._mutate_random_byte(fuzzed_data)

            self._check_and_report(fuzzed_data)
            fuzz_iterations += 1
            
            if fuzz_iterations % 100 == 0:
                elapsed = time.time() - self.start_time
                remaining = int(end_time - time.time())
                print(f"[+] Progress: {self.total_tests} tests executed. Elapsed: {elapsed:.2f}s. Remaining: {remaining}s...")

        print(f"\n[!] Fuzzing finished for {os.path.basename(self.target)}. Timeout reached after {self.total_tests} tests.")
        
        # *** 关键修改 3: 返回崩溃数据 ***
        return self.crashes, self.crashing_inputs


    def _check_and_report(self, input_data):
        """检查是否发现崩溃，并在发现崩溃时将输入数据存储在内存中。"""
        
        if self._execute_target(input_data):
            # *** 关键修改 4: 不再写入文件，而是存储在内存中 ***
            self.crashing_inputs.append(input_data) 
            
            message = f"[!!!] CRASH FOUND! Input recorded in memory for {os.path.basename(self.target)}."
            self.crashes.append(message)
            print(message)
            return True
        return False


def consolidate_crashing_inputs(crashing_data_map, output_path):
    """将所有崩溃输入写入 bad_<binary>.txt 文件中。"""
    
    os.makedirs(output_path, exist_ok=True)
    
    print("\n\n=== Txt Start ===")
    consolidated_files = []
    
    for target_name, inputs_list in crashing_data_map.items():
        if not inputs_list:
             continue
             
        output_filename = f"bad_{target_name}.txt"
        output_filepath = os.path.join(output_path, output_filename)
        
        print(f"[*] write {len(inputs_list)} in '{output_filepath}'")
        
        # 使用 'wb' 模式写入二进制数据
        with open(output_filepath, 'wb') as outfile: 
            for i, input_data in enumerate(inputs_list):
                # 写入分隔符 (编码为 bytes)
                separator = f"\n\n--- Input {i+1} / {len(inputs_list)} ---\n".encode('utf-8')
                outfile.write(separator)
                # 写入实际的崩溃数据
                outfile.write(input_data)
                
        consolidated_files.append(output_filename)
                
    print("[+] Success！")
    print(f"In '{output_path}' folder：")
    for filename in consolidated_files:
        print(f"  - {filename}")
    print("=====================")


def run_fuzzing_campaign(targets, output_path):
    """
    管理针对多个二进制文件的整个模糊测试活动。
    """
    
    total_campaign_start = time.time()
    all_crashes = []
    # 用于存储所有崩溃数据的字典：{'csv2': [data1, data2, ...]}
    all_crashing_data = defaultdict(list) 
    
    for binary_path, seed in targets:
        binary_name = os.path.basename(binary_path)
        
        fuzzer = Fuzzer(binary_path, seed, timeout=TIMEOUT_PER_BINARY)
        # *** 关键修改 5: 接收崩溃数据 ***
        crashes_messages, crashing_data = fuzzer.run() 
        
        if crashes_messages:
            all_crashes.extend(crashes_messages)
        
        if crashing_data:
            all_crashing_data[binary_name].extend(crashing_data)
        
        print("-" * 50)
    
    # *** 关键修改 6: 在活动结束时调用整合函数 ***
    consolidate_crashing_inputs(all_crashing_data, output_path)
    
    total_time = time.time() - total_campaign_start
    
    print("\n\n=== CAMPAIGN SUMMARY ===")
    print(f"Total time elapsed: {total_time:.2f} seconds")
    if all_crashes:
        print(f"Total crashes found: {len(all_crashes)}")
        # 打印崩溃消息 (现在它们只说 "Input recorded in memory")
        print("Crash details are stored in the 'bad_*.txt' files.")
    else:
        print("No crashes found across all targets.")
    print("========================")


if __name__ == '__main__':
    
    # 路径逻辑 (已确认正确)：
    CWD = os.getcwd()
    
    # 种子文件路径 (../example_inputs)
    SEED_DIR_RELATIVE = os.path.join('..', 'example_inputs')
    SEED_DIR_ABSOLUTE = os.path.abspath(os.path.join(CWD, SEED_DIR_RELATIVE))
    
    # 目标二进制文件路径 (../binaries)
    TARGET_DIR_RELATIVE = os.path.join('..', 'binaries')
    TARGET_DIR_ABSOLUTE = os.path.abspath(os.path.join(CWD, TARGET_DIR_RELATIVE))
    
    # 输出文件路径 (../find_output)
    FIND_OUTPUT_DIR = "find_output"
    OUTPUT_PATH = os.path.abspath(os.path.join(CWD, '..', FIND_OUTPUT_DIR))

    targets_to_fuzz = [
        (os.path.join(TARGET_DIR_ABSOLUTE, 'csv1'), os.path.join(SEED_DIR_ABSOLUTE, 'csv1.txt')),
        (os.path.join(TARGET_DIR_ABSOLUTE, 'csv2'), os.path.join(SEED_DIR_ABSOLUTE, 'csv2.txt')),
        (os.path.join(TARGET_DIR_ABSOLUTE, 'json1'), os.path.join(SEED_DIR_ABSOLUTE, 'json1.txt')),
        (os.path.join(TARGET_DIR_ABSOLUTE, 'json2'), os.path.join(SEED_DIR_ABSOLUTE, 'json2.txt')),
    ]

    print(f"Current working directory: {CWD}")
    print(f"Seed directory (Absolute): {SEED_DIR_ABSOLUTE}")
    print(f"Target binary directory (Absolute): {TARGET_DIR_ABSOLUTE}")
    print(f"Crash outputs will be consolidated to: {OUTPUT_PATH}")
    
    sys.stdout.flush()
    
    run_fuzzing_campaign(targets_to_fuzz, OUTPUT_PATH)
    
