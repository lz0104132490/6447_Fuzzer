import os
import sys
import time
import random
import struct
import signal
import subprocess
from pathlib import Path
from collections import defaultdict
import hashlib
import re
import traceback

class XMLFuzzer:
    def __init__(self, binary_path, example_input_path, output_dir):
        self.binary_path = binary_path
        self.example_input_path = example_input_path
        self.output_dir = output_dir
        self.prog_name = os.path.basename(binary_path)
        
        # Coverage tracking
        self.coverage_map = set()
        self.interesting_inputs = []
        
        # Statistics
        self.total_executions = 0
        self.crashes_found = 0
        self.hangs_found = 0
        self.unique_crashes = set() 
        
        # Timeout settings
        self.timeout = 1
        self.hang_timeout = 3
        
        # Load example input
        self.seed_input = self._load_seed_input()
        
        # XML/HTML-specific tokens and structures
        self.xml_tokens = [
            b'<?xml', b'version=', b'encoding=', b'?>',
            b'<', b'>', b'</', b'/>', b'<!DOCTYPE', b'<!ENTITY',
            b'CDATA', b'&', b';', b'',
            b'xmlns', b'xsi:', b'schemaLocation',
            b'<html', b'<head', b'<body', b'<div', b'<a', b'<script',
            b'href=', b'src=', b'id=', b'class=', b'style=',
            b'</html>', b'</head>', b'</body>', b'</div>',
        ]
        
        # Known bad values for XML/HTML
        self.bad_values = [
            b'&' * 10000,
            b'<' * 1000,
            b'>' * 1000,
            b'<tag>' * 10000,
            b'\x00' * 100,
            b'\xff' * 100,
            b'A' * 100000,
            b'../../../etc/passwd',
            b'file:///etc/passwd',
            b'<script>alert(1)</script>',
            b'javascript:alert(1)',
            b'onerror=alert(1)',
            b'\'" onclick=alert(1)//',
            b'http://' + b'A' * 10000,
            b'href="' + b'x' * 100000 + b'"',
            b'id="' + b'#' * 10000 + b'"',
            b'class="' + b' ' * 10000 + b'"',
            b'<div>' * 10000,
            b'<a href="x">' * 1000,
        ]
        
        # Magic numbers
        self.magic_numbers = [
            0, -1, 0x7fffffff, 0x80000000, 0xffffffff,
            255, 256, 65535, 65536, -32768, 32767
        ]

    def _load_seed_input(self):
        try:
            with open(self.example_input_path, 'rb') as f:
                return f.read()
        except Exception as e:
            print(f"Error loading seed: {e}")
            return b'<?xml version="1.0"?><root>test</root>'

    def _hash_input(self, data):
        return hashlib.md5(data).hexdigest()

    def _run_target(self, input_data):
        try:
            start_time = time.time()
            
            proc = subprocess.Popen(
                [self.binary_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid
            )
            
            try:
                stdout, stderr = proc.communicate(input_data, timeout=self.timeout)
                exit_code = proc.returncode
                signal_num = None
                
                if exit_code < 0:
                    signal_num = -exit_code
                    
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                proc.communicate()
                return (-1, signal.SIGKILL, None, time.time() - start_time)
            
            execution_time = time.time() - start_time
            coverage_hash = self._approximate_coverage(exit_code, len(stdout), len(stderr))
            self.total_executions += 1
            
            return (exit_code, signal_num, coverage_hash, execution_time)
            
        except Exception as e:
            print(f"Execution error: {e}")
            return (0, None, None, 0)

    def _approximate_coverage(self, exit_code, stdout_len, stderr_len):
        return f"{exit_code}:{stdout_len}:{stderr_len}"

    def _is_crash(self, exit_code, signal_num):
        crash_signals = [
            signal.SIGSEGV, signal.SIGABRT, signal.SIGILL,
            signal.SIGFPE, signal.SIGBUS
        ]
        
        if signal_num in crash_signals:
            return True
        
        if exit_code in [139, 134, 136]:
            return True
            
        return False

    def _is_hang(self, execution_time):
        return execution_time >= self.hang_timeout

    def _save_crash(self, input_data, crash_type="crash"):
        output_file = os.path.join(self.output_dir, f"bad_{self.prog_name}.txt")
        
        crash_hash = self._hash_input(input_data)
        is_new_unique_crash = False

        
        if crash_hash not in self.unique_crashes:
            self.unique_crashes.add(crash_hash)
            self.crashes_found += 1
            is_new_unique_crash = True
        
       
        try:
            # append binary
            with open(output_file, 'ab') as f:
                separator = b"\n" + b"="*80 + b"\n"
                
                meta_data = (
                    f"--- START CRASH SAMPLE ---\n"
                    f"Type: {crash_type}\n"
                    f"Hash: {crash_hash}\n"
                    f"Size: {len(input_data)} bytes\n"
                    f"Unique: {'YES' if is_new_unique_crash else 'NO'}\n"
                    f"--- BEGIN DATA ---\n"
                ).encode('utf-8')
                
              
                f.write(separator)
                f.write(meta_data)
                f.write(input_data)
                f.write(b"\n--- END DATA ---\n")

            #if is_new_unique_crash:            
                #print(f"\nSaved first instance of unique {crash_type} to: {output_file}")
            
            return True

        except Exception as e:
            print(f"Error saving crash: {e}")
            return False
   
    def _generate_deterministic_mutations(self, data):
        """Generate deterministic mutations targeting format string vulnerability"""
        mutations = []
        
        # Strategy 1: Target ALL attributes with format strings (not just href)
        
        attributes_to_test = [
            b'href', b'src', b'id', b'class', b'style', b'name', 
            b'value', b'type', b'content', b'data', b'alt', b'title'
        ]
        
        format_payloads = [
            b'%s', b'%s%s', b'%s%s%s', b'%s%s%s%s', b'%s%s%s%s%s',
            b'%s' * 10, b'%s' * 20,
            b'%n', b'%n%n', b'%n%n%n',
            b'%s%n', b'%s%s%n',
            b'%p' * 10, b'%x' * 10,
            b'%10000s', b'%1$s', b'%10$s',
        ]
        
        # Test format strings in ALL tags 
        tags = re.findall(rb'<([a-zA-Z][a-zA-Z0-9]*)', data)
        unique_tags = list(set(tags))
        
        print(f"Found tags: {unique_tags}")
        
        for tag in unique_tags:
            for attr in attributes_to_test:
                for payload in format_payloads[:15]:  # Test first 15 payloads per attr
                    # Pattern: <tag attr="payload">
                    # This attempt to insert attribute might fail if the tag is self-closing or already has attributes.
                    # A more robust regex is hard, so we stick to a simple one.
                    result = re.sub(
                        rb'<' + tag + rb'([^>]*)>',
                        b'<' + tag + b' ' + attr + b'="' + payload + b'"\\1>',
                        data, count=1
                    )
                    mutations.append(result)
        
        # specifically target link href
        if b'<link' in data:
            print("Detected <link> tag - adding specific href payloads")
            for payload in format_payloads:
                result = re.sub(rb'href="[^"]*"', b'href="' + payload + b'"', data)
                mutations.append(result)
        
        # Test format strings in text content of tags
        for tag in unique_tags[:5]:  # Limit to first 5 tags
            for payload in format_payloads[:10]:
                result = re.sub(
                    rb'(<' + tag + rb'[^>]*>)([^<]*)(</?' + tag + rb'>)',
                    rb'\1' + payload + rb'\3',
                    data, count=1
                )
                mutations.append(result)
        
        # Tag corruption
        for tag in unique_tags[:3]:
            for i in range(1, min(len(tag), 3)):
                result = data.replace(b'<' + tag + b'>', b'<' + tag[:i] + b'</a>', 1)
                mutations.append(result)
        
        print(f"Generated {len(mutations)} total test cases")
        return mutations

    def _bit_flip(self, data):
        if len(data) == 0:
            return data
        result = bytearray(data)
        num_flips = random.randint(1, min(10, len(data)))
        for _ in range(num_flips):
            byte_idx = random.randint(0, len(result) - 1)
            bit_idx = random.randint(0, 7)
            result[byte_idx] ^= (1 << bit_idx)
        return bytes(result)

    def _byte_flip(self, data):
        if len(data) == 0:
            return data
        result = bytearray(data)
        num_flips = random.randint(1, min(10, len(data)))
        for _ in range(num_flips):
            idx = random.randint(0, len(result) - 1)
            result[idx] = random.randint(0, 255)
        return bytes(result)

    def _insert_magic_numbers(self, data):
        if len(data) < 4:
            return data
        result = bytearray(data)
        idx = random.randint(0, len(result) - 4)
        magic = random.choice(self.magic_numbers)
        if random.choice([True, False]):
            result[idx:idx+4] = struct.pack('<I', magic & 0xffffffff)
        else:
            result[idx:idx+4] = struct.pack('>I', magic & 0xffffffff)
        return bytes(result)

    def _duplicate_chunk(self, data):
        if len(data) < 10:
            return data
        result = bytearray(data)
        chunk_size = random.randint(1, min(100, len(data) // 2))
        start = random.randint(0, len(data) - chunk_size)
        chunk = result[start:start + chunk_size]
        repetitions = random.randint(2, 100)
        result = result[:start] + chunk * repetitions + result[start + chunk_size:]
        return bytes(result)

    def _extract_and_insert_xml_keywords(self, data):
        result = bytearray(data)
        found_tokens = [token for token in self.xml_tokens if token in data]
        if found_tokens and len(result) > 0:
            token = random.choice(found_tokens)
            insert_pos = random.randint(0, len(result))
            repetitions = random.randint(1, 50)
            result = result[:insert_pos] + token * repetitions + result[insert_pos:]
        return bytes(result)

    def _arithmetic_mutations(self, data):
        if len(data) == 0:
            return data
        result = bytearray(data)
        num_mutations = random.randint(1, min(5, len(data)))
        for _ in range(num_mutations):
            idx = random.randint(0, len(result) - 1)
            operation = random.choice(['add', 'sub', 'xor'])
            value = random.randint(1, 255)
            if operation == 'add':
                result[idx] = (result[idx] + value) & 0xff
            elif operation == 'sub':
                result[idx] = (result[idx] - value) & 0xff
            else:
                result[idx] ^= value
        return bytes(result)

    def _splice_inputs(self, data):
        if not self.interesting_inputs:
            return data
        other = random.choice(self.interesting_inputs)
        point1 = random.randint(0, len(data))
        point2 = random.randint(0, len(other))
        return data[:point1] + other[point2:]

    def _coverage_guided_mutation(self, data):
        mutated = random.choice([
            self._bit_flip,
            self._byte_flip,
            self._insert_magic_numbers,
            self._duplicate_chunk
        ])(data)
        
        exit_code, signal_num, coverage_hash, exec_time = self._run_target(mutated)
        
        if coverage_hash and coverage_hash not in self.coverage_map:
            self.coverage_map.add(coverage_hash)
            self.interesting_inputs.append(mutated)
            return mutated
        return data

    def _insert_xml_bombs(self, data):
        result = bytearray(data)
        bomb_patterns = [
            b'<!DOCTYPE lol [<!ENTITY lol "lol"><!ENTITY lol1 "&lol;&lol;&lol;">]>',
            b'<!ENTITY xxe SYSTEM "file:///etc/passwd">',
            b'&' + b'x' * 1000 + b';',
            b'<tag>' * 1000 + b'</tag>' * 1000,
            b'<script>while(1){}</script>',
            b'<iframe src="javascript:alert(1)">',
            b'<a href="' + b'x' * 100000 + b'">link</a>',
            b'<div id="' + b'#' * 10000 + b'">',
            b'<div>' * 1000 + b'content' + b'</div>' * 1000,
            b'<a href="x">' * 500 + b'link' + b'</a>' * 500,
            b'<a href="' + b'\x00' * 100 + b'">',
            b'<link href="' + b'A' * 100000 + b'" />',
            b'<body ' + b'x="1" ' * 10000 + b'>',
            b'<div style="' + b'color:red;' * 1000 + b'">',
        ]
        pattern = random.choice(bomb_patterns)
        insert_pos = random.randint(0, len(result))
        result = result[:insert_pos] + pattern + result[insert_pos:]
        return bytes(result)

    def _malform_html_structure(self, data):
        result = bytearray(data)
        mutations = [
            lambda d: d.replace(b'<html', b'<html' * 100),
            lambda d: d.replace(b'</html>', b''),
            lambda d: d.replace(b'<head', b'<head><head><head'),
            lambda d: d.replace(b'</body>', b'</body></body></body>'),
            lambda d: d.replace(b'<div', b'<div' * 50),
            lambda d: d.replace(b'href="', b'href=""href="'),
            lambda d: d.replace(b'id="', b'id="' + b'#' * 1000),
            lambda d: d.replace(b'">', b'"' * 100 + b'>'),
            lambda d: d.replace(b'http://', b'http://' * 100),
            lambda d: d.replace(b'"', b''),
            lambda d: d.replace(b'"', b"'"),
            lambda d: d.replace(b'="', b'='),
            lambda d: d.replace(b'</', b'<'),
            lambda d: d.replace(b'/>', b'>'),
            lambda d: d.replace(b'>', b'>>'),
            lambda d: d.replace(b'<', b'<<'),
            lambda d: d + b'<unclosed>',
            lambda d: d.replace(b'</div>', b''),
            lambda d: d.replace(b'</a>', b''),
        ]
        mutation = random.choice(mutations)
        return mutation(bytes(result))

    def _corrupt_html_tags(self, data):
        result = bytearray(data)
        html_corruptions = [
            (b'<html>', b'<html' * 100 + b'>'),
            (b'<head>', b'<head><head><head>'),
            (b'<body>', b'<body ' + b'x' * 1000 + b'>'),
            (b'<div', b'<div' * 50),
            (b'<a href=', b'<a href=' * 10),
            (b'</html>', b''),
            (b'</head>', b'<head>'),
            (b'</body>', b'<body>'),
            (b'href="http://', b'href="' + b'x' * 10000),
            (b'id="#', b'id="' + b'#' * 10000),
            (b'.com"', b'.com' + b'x' * 1000 + b'"'),
        ]
        old, new = random.choice(html_corruptions)
        if old in result:
            result = result.replace(old, new, 1)
        return bytes(result)

    def _aggressive_tag_corruption(self, data):
        result = bytearray(data)
        tags = re.findall(rb'<([a-zA-Z][a-zA-Z0-9]*)', bytes(result))
        
        if not tags:
            return bytes(result)
        
        target_tag = random.choice(tags)
        
        corruptions = [
            lambda t, d: d.replace(b'<' + t, b'<' + t[:random.randint(1, max(1, len(t)-1))], 1),
            lambda t, d: d.replace(b'<' + t + b'>', b'<' + t, 1),
            lambda t, d: d.replace(b'<' + t + b'>', b'<' + t + b'xxx>', 1),
            lambda t, d: d.replace(b'<' + t + b'>', b'<' + t + b'</a>', 1),
            lambda t, d: d.replace(b'<' + t, b'<' + t + t, 1),
            lambda t, d: d.replace(b'<' + t + b'>', b'<' + t + b'\x00>', 1),
            lambda t, d: d.replace(b'</' + t + b'>', b'', 1),
            lambda t, d: d.replace(b'<' + t + b'>', b'</' + t + b'>', 1),
            lambda t, d: d.replace(b'</' + t + b'>', b'</' + t[:random.randint(1, max(1, len(t)-1))], 1),
        ]
        
        corruption = random.choice(corruptions)
        try:
            result = bytearray(corruption(target_tag, bytes(result)))
        except:
            pass
        return bytes(result)

    def _partial_tag_deletion(self, data):
        result = bytearray(data)
        if b'<' in result:
            positions = [i for i, b in enumerate(result) if b == ord(b'<')]
            if positions:
                pos = random.choice(positions)
                delete_len = random.randint(1, min(5, len(result) - pos - 1))
                result = result[:pos+1] + result[pos+1+delete_len:]
        return bytes(result)

    def _random_tag_mutations(self, data):
        result = bytearray(data)
        tag_positions = [i for i, b in enumerate(result) if b == ord(b'<')]
        if not tag_positions:
            return bytes(result)
        pos = random.choice(tag_positions)
        for i in range(random.randint(1, 3)):
            if pos + 1 + i < len(result):
                result[pos + 1 + i] = random.randint(ord('a'), ord('z'))
        return bytes(result)

    def _insert_bad_values(self, data):
        result = bytearray(data)
        bad_value = random.choice(self.bad_values)
        insert_pos = random.randint(0, len(result))
        result = result[:insert_pos] + bad_value + result[insert_pos:]
        return bytes(result)

    def _overflow_link_href(self, data):
        """Target the format string vulnerability in printf(buf)"""
        if b'<link' not in data and b'href=' not in data: # Check for link or any href
            # Fallback to general href check if <link is not present, though it's less focused
            if b'href=' not in data:
                return data

        # Format string payloads - much more effective than buffer overflow
        payloads = [
            b'%s',
            b'%s%s%s',
            b'%s%s%s%s%s',
            b'%s' * 10,
            b'%s' * 20,
            b'%n',
            b'%n%n%n',
            b'%s%n',
            b'%p' * 10,
            b'%x' * 10,
            b'%s%s%p%p%n',
            b'%10000s',
            b'%99999s',
            b'%1$s',
            b'%10$s',
            b'%100$s',
            b'%1$n',
            b'AAAA%s%s%s',
        ]
        
        payload = random.choice(payloads)
        # Attempt to replace ANY href attribute value
        result = re.sub(rb'href="[^"]*"', b'href="' + payload + b'"', data)
        return result

    def mutate(self, data):
        strategies = [
            # HIGHEST PRIORITY: Link href overflow 
            (self._overflow_link_href, 0.40),
            
            # Basic mutations 
            (self._bit_flip, 0.03),
            (self._byte_flip, 0.03),
            (self._insert_magic_numbers, 0.03),
            (self._insert_bad_values, 0.03),
            (self._duplicate_chunk, 0.03),
            
            # Intermediate mutations 
            (self._extract_and_insert_xml_keywords, 0.03),
            (self._arithmetic_mutations, 0.03),
            (self._malform_html_structure, 0.09),
            
            # Advanced mutations
            (self._coverage_guided_mutation, 0.02),
            (self._splice_inputs, 0.02),
            (self._insert_xml_bombs, 0.05),
            (self._corrupt_html_tags, 0.06),
            (self._aggressive_tag_corruption, 0.10),
            (self._partial_tag_deletion, 0.05),
            (self._random_tag_mutations, 0.03),
        ]
        
        rand = random.random()
        cumulative = 0
        
        for strategy, weight in strategies:
            cumulative += weight
            if rand < cumulative:
                return strategy(data)
        
        return self._bit_flip(data)

    def fuzz(self, time_limit=60):
        print(f"Starting fuzzer for {self.prog_name}")
        print(f"Binary: {self.binary_path}")
        print(f"Seed: {self.example_input_path}")
        print(f"Time limit: {time_limit} seconds")
        print("-" * 60)
        
        start_time = time.time()
        last_stats_time = start_time
        iteration = 0
        crash_found = False
        
        self.interesting_inputs.append(self.seed_input)
        
        print("Phase 1: Deterministic format string attacks...")
        deterministic_mutations = self._generate_deterministic_mutations(self.seed_input)
        
        print(f"Testing {len(deterministic_mutations)} deterministic payloads")
        
        for idx, mutated in enumerate(deterministic_mutations):
            if (time.time() - start_time) > 20:
                print(f"\nPhase 1 timeout after {idx} test cases")
                break
            
            if crash_found and idx > 50:  # Continue testing a bit after first crash
                break
            
            exit_code, signal_num, coverage_hash, exec_time = self._run_target(mutated)
            iteration += 1
            
            if self._is_crash(exit_code, signal_num):
                crash_type = f"CRASH (signal={signal_num}, exit={exit_code})"
                print(f"\n{crash_type} at iteration {iteration} (payload #{idx})")
                
                # Print the payload that caused crash
                href_match = re.search(rb'href="([^"]*)"', mutated)
                if href_match:
                    payload = href_match.group(1)
                    print(f"Crashing payload: href=\"{payload[:100]}\"")
                
                if self._save_crash(mutated, crash_type):
                    crash_found = True
                    print(f"First crash saved! Continuing to test remaining payloads...")
            
            if coverage_hash and coverage_hash not in self.coverage_map:
                self.coverage_map.add(coverage_hash)
                if len(mutated) < 100000:
                    self.interesting_inputs.append(mutated)
            
            # Progress indicator every 10 payloads
            if (idx + 1) % 10 == 0:
                print(f"Tested {idx + 1}/{len(deterministic_mutations)} payloads, crash_found={crash_found}")
        
        print(f"\nPhase 1 completed. Iterations: {iteration}, Crash found: {crash_found}")
        
        print("Phase 2: Random format string mutations...")
        
        while (time.time() - start_time) < time_limit:
            if self.interesting_inputs and random.random() < 0.9:
                base_input = random.choice(self.interesting_inputs)
            else:
                base_input = self.seed_input
            
            mutated = self.mutate(base_input)
            
            if len(mutated) > 1000000:
                mutated = mutated[:1000000]
            
            exit_code, signal_num, coverage_hash, exec_time = self._run_target(mutated)
            
            if self._is_crash(exit_code, signal_num):
                crash_type = f"CRASH (signal={signal_num}, exit={exit_code})" 
                self._save_crash(mutated, crash_type)
            
            if self._is_hang(exec_time):
                print(f"\nHANG detected at iteration {iteration}")
                self.hangs_found += 1
                self._save_crash(mutated, "hang")
            
            if coverage_hash and coverage_hash not in self.coverage_map:
                self.coverage_map.add(coverage_hash)
                if len(mutated) < 100000:
                    self.interesting_inputs.append(mutated)
            
            iteration += 1
            
            current_time = time.time()
            if current_time - last_stats_time >= 5:
                elapsed = current_time - start_time
                remaining = time_limit - elapsed
                print(f"\rTime: {elapsed:.1f}s/{time_limit}s (Remaining: {remaining:.1f}s)", end='')
                self._print_stats(iteration, elapsed)
                last_stats_time = current_time
        
        print("\n" + "=" * 60)
        elapsed_total = time.time() - start_time
        print(f"Fuzzing completed in {elapsed_total:.2f} seconds")
        self._print_stats(iteration, elapsed_total)
        print("=" * 60)

    def _print_stats(self, iteration, elapsed_time):
        execs_per_sec = self.total_executions / elapsed_time if elapsed_time > 0 else 0
        print(f"\rIter: {iteration:6d} | "
              f"Execs: {self.total_executions:6d} | "
              f"Speed: {execs_per_sec:6.1f} exec/s | "
              f"Coverage: {len(self.coverage_map):4d} | "
              f"Crashes: {self.crashes_found:3d} | "
              f"Hangs: {self.hangs_found:3d}", end='')


def main():
    print("XML Fuzzer starting...")
    
    binaries_dir = "/binaries"
    example_inputs_dir = "/example_inputs"
    output_dir = "/fuzzer_output"
    TIME_LIMIT_PER_BINARY = 60
    
    os.makedirs(output_dir, exist_ok=True)
    
    xml_binaries = []
    
    try:
        for binary_file in os.listdir(binaries_dir):
            binary_path = os.path.join(binaries_dir, binary_file)
            
            if os.path.isfile(binary_path) and os.access(binary_path, os.X_OK):
                example_input = os.path.join(example_inputs_dir, f"{binary_file}.txt")
                
                if os.path.exists(example_input):
                    with open(example_input, 'rb') as f:
                        content = f.read(1000)
                        if (b'xml' in content.lower() or b'<' in content or 
                            b'html' in content.lower() or b'<!DOCTYPE' in content or
                            b'<head' in content.lower() or b'<body' in content.lower()):
                            xml_binaries.append((binary_path, example_input))
                            print(f"Found XML binary: {binary_file}")
    except Exception as e:
        print(f"Error scanning binaries: {e}")
    
    if not xml_binaries:
        print("No XML binaries found")
        return
    
    total_expected_time = len(xml_binaries) * TIME_LIMIT_PER_BINARY
    print(f"\nTotal binaries to fuzz: {len(xml_binaries)}")
    print(f"Time limit per binary: {TIME_LIMIT_PER_BINARY} seconds")
    print(f"Total expected time: {total_expected_time} seconds ({total_expected_time/60:.1f} minutes)")
    
    overall_start = time.time()
    
    for idx, (binary_path, example_input) in enumerate(xml_binaries, 1):
        print(f"\n{'='*60}")
        print(f"Fuzzing {idx}/{len(xml_binaries)}: {os.path.basename(binary_path)}")
        print(f"{'='*60}\n")
        
        binary_start = time.time()
        fuzzer = XMLFuzzer(binary_path, example_input, output_dir)
        
        try:
            fuzzer.fuzz(time_limit=TIME_LIMIT_PER_BINARY)
        except KeyboardInterrupt:
            print("\nFuzzing interrupted by user")
            break
        except Exception as e:
            print(f"Error during fuzzing: {e}")
            #import traceback
            traceback.print_exc()
            continue
        
        binary_elapsed = time.time() - binary_start
        print(f"Binary completed in {binary_elapsed:.2f} seconds")
        
        elapsed = time.time() - overall_start
        remaining_binaries = len(xml_binaries) - idx
        estimated_remaining = remaining_binaries * TIME_LIMIT_PER_BINARY
        print(f"Overall progress: {idx}/{len(xml_binaries)} binaries")
        print(f"Time elapsed: {elapsed:.1f}s, Estimated remaining: {estimated_remaining:.1f}s")
    
    overall_elapsed = time.time() - overall_start
    print("\n" + "="*60)
    print(f"All fuzzing completed in {overall_elapsed:.2f} seconds ({overall_elapsed/60:.1f} minutes)")
    print("="*60)


if __name__ == "__main__":
    main()
