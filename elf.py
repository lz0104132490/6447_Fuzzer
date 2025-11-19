import os
import sys
import time
import random
import struct
import signal
import subprocess
import hashlib
import traceback

class ELFFuzzer:
    def __init__(self, binary_path, example_input_path, output_dir):
        self.binary_path = binary_path
        self.example_input_path = example_input_path
        self.output_dir = output_dir
        self.prog_name = os.path.basename(binary_path)
        
        # Statistics
        self.total_executions = 0
        self.crashes_found = 0
        self.unique_crashes = set()
        self.coverage_map = set()
        self.interesting_inputs = []
        
        # Timeout settings
        self.timeout = 1
        
        # Load seed
        self.seed_input = self._load_seed_input()
        
        # ELF structure offsets (64-bit)
        self.ELF_MAGIC = b'\x7fELF'
        self.EHDR_SIZE = 64
        self.PHDR_SIZE = 56
        self.SHDR_SIZE = 64

    def _load_seed_input(self):
        try:
            with open(self.example_input_path, 'rb') as f:
                return f.read()
        except Exception as e:
            print(f"Error loading seed: {e}")
            # Return minimal ELF
            return self._generate_minimal_elf()

    def _generate_minimal_elf(self):
        elf = bytearray()
        
        # ELF Header (64 bytes)
        elf.extend(b'\x7fELF')  # Magic
        elf.extend(b'\x02')     # 64-bit
        elf.extend(b'\x01')     # Little endian
        elf.extend(b'\x01')     # ELF version
        elf.extend(b'\x00' * 9) # Padding
        
        elf.extend(struct.pack('<H', 0x02))  # e_type: ET_EXEC
        elf.extend(struct.pack('<H', 0x3e))  # e_machine: x86-64
        elf.extend(struct.pack('<I', 0x01))  # e_version
        elf.extend(struct.pack('<Q', 0x00))  # e_entry
        elf.extend(struct.pack('<Q', 0x40))  # e_phoff
        elf.extend(struct.pack('<Q', 0x00))  # e_shoff
        elf.extend(struct.pack('<I', 0x00))  # e_flags
        elf.extend(struct.pack('<H', 0x40))  # e_ehsize
        elf.extend(struct.pack('<H', 0x38))  # e_phentsize
        elf.extend(struct.pack('<H', 0x01))  # e_phnum
        elf.extend(struct.pack('<H', 0x40))  # e_shentsize
        elf.extend(struct.pack('<H', 0x00))  # e_shnum
        elf.extend(struct.pack('<H', 0x00))  # e_shstrndx
        
        return bytes(elf)

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
            coverage_hash = f"{exit_code}:{len(stdout)}:{len(stderr)}"
            self.total_executions += 1
            
            return (exit_code, signal_num, coverage_hash, execution_time)
            
        except Exception as e:
            return (0, None, None, 0)

    def _is_crash(self, exit_code, signal_num):
        crash_signals = [
            signal.SIGSEGV, signal.SIGABRT, signal.SIGILL,
            signal.SIGFPE, signal.SIGBUS
        ]
        return signal_num in crash_signals or exit_code in [139, 134, 136]

    def _save_crash(self, input_data, crash_type="crash"):
        output_file = os.path.join(self.output_dir, f"bad_{self.prog_name}.txt")
        
        if not os.path.exists(output_file):
            try:
                with open(output_file, 'wb') as f:
                    f.write(input_data)
                print(f"\nSaved {crash_type}: {output_file}")
                self.crashes_found += 1
                return True
            except Exception as e:
                print(f"Error saving crash: {e}")
        else:
            crash_hash = self._hash_input(input_data)
            if crash_hash not in self.unique_crashes:
                self.unique_crashes.add(crash_hash)
                self.crashes_found += 1
                print(f"\nFound additional unique {crash_type}")
        
        return False

    
    def _mutate_elf_header(self, data):
        if len(data) < self.EHDR_SIZE:
            return data
        
        result = bytearray(data)
        
        mutations = [
            lambda d: self._set_bytes(d, 0, b'\x7f' + b'ELX'),
            lambda d: self._set_u16(d, 60, 0xFFFF),  # e_shnum
            lambda d: self._set_u16(d, 56, 0xFFFF),  # e_phnum
            lambda d: self._set_u16(d, 62, 0xFFFF),  # e_shstrndx
            lambda d: self._set_u64(d, 32, 0xFFFFFFFFFFFFFFFF),  # e_phoff
            lambda d: self._set_u64(d, 40, 0xFFFFFFFFFFFFFFFF),  # e_shoff
            lambda d: self._set_u16(d, 52, 0xFFFF),  # e_ehsize
            lambda d: self._set_u16(d, 54, 0x0001),  # e_phentsize
            lambda d: self._set_u16(d, 58, 0x0001),  # e_shentsize
        ]
        
        mutation = random.choice(mutations)
        return bytes(mutation(result))

    def _mutate_program_headers(self, data):
        if len(data) < self.EHDR_SIZE:
            return data
        
        result = bytearray(data)

        e_phoff = struct.unpack('<Q', result[32:40])[0]
        e_phnum = struct.unpack('<H', result[56:58])[0]
        
        if e_phoff > 0 and e_phoff + self.PHDR_SIZE <= len(result):
            mutations = [             
                lambda d, off: self._set_u64(d, off + 32, 0xFFFFFFFFFFFFFFFF),               
                lambda d, off: self._set_u64(d, off + 40, 0xFFFFFFFFFFFFFFFF),               
                lambda d, off: self._set_u64(d, off + 8, 0xFFFFFFFFFFFFFFFF),             
                lambda d, off: self._set_u32(d, off, 0xFFFFFFFF),
            ]
            
            mutation = random.choice(mutations)
            result = bytearray(mutation(result, e_phoff))
        
        return bytes(result)

    def _mutate_section_headers(self, data):     
        if len(data) < self.EHDR_SIZE:
            return data
        
        result = bytearray(data)
   
        e_shoff = struct.unpack('<Q', result[40:48])[0]
        e_shnum = struct.unpack('<H', result[60:62])[0]
        
        if e_shoff > 0 and e_shoff + self.SHDR_SIZE <= len(result):
            mutations = [
                lambda d, off: self._set_u32(d, off, 0xFFFFFFFF),
                lambda d, off: self._set_u64(d, off + 32, 0xFFFFFFFFFFFFFFFF),
                lambda d, off: self._set_u64(d, off + 24, 0xFFFFFFFFFFFFFFFF),
                lambda d, off: self._set_u32(d, off + 4, 0xFFFFFFFF),
            ]
            
            mutation = random.choice(mutations)
            result = bytearray(mutation(result, e_shoff))
        
        return bytes(result)

    def _corrupt_string_table(self, data):
        if len(data) < self.EHDR_SIZE:
            return data
        
        result = bytearray(data)
        
        if len(result) > 100:
            pos = random.randint(50, len(result) - 50)
            long_string = b'A' * random.randint(100, 500)
            result[pos:pos+len(long_string)] = long_string
        
        return bytes(result)

    def _create_nested_sections(self, data):
        if len(data) < self.EHDR_SIZE:
            return data
        
        result = bytearray(data)

        if len(result) >= 62:
            current_shnum = struct.unpack('<H', result[60:62])[0]
            new_shnum = min(current_shnum + random.randint(1, 10), 100)
            struct.pack_into('<H', result, 60, new_shnum)
        
        return bytes(result)

    def _integer_overflow_attack(self, data):
        if len(data) < self.EHDR_SIZE:
            return data
        
        result = bytearray(data)
        
        overflow_values = [
            0xFFFFFFFF, 0xFFFFFFFE, 0x7FFFFFFF, 0x80000000,
            0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE
        ]
        
        if len(result) >= 64:
            pos = random.choice([32, 40, 56, 60])  
            if pos + 8 <= len(result):
                value = random.choice(overflow_values)
                if value <= 0xFFFFFFFF:
                    struct.pack_into('<I', result, pos, value & 0xFFFFFFFF)
                else:
                    struct.pack_into('<Q', result, pos, value)
        
        return bytes(result)

    def _set_bytes(self, data, offset, value):
        for i, b in enumerate(value):
            if offset + i < len(data):
                data[offset + i] = b
        return data

    def _set_u16(self, data, offset, value):
        if offset + 2 <= len(data):
            struct.pack_into('<H', data, offset, value)
        return data

    def _set_u32(self, data, offset, value):
        if offset + 4 <= len(data):
            struct.pack_into('<I', data, offset, value)
        return data

    def _set_u64(self, data, offset, value):
        if offset + 8 <= len(data):
            struct.pack_into('<Q', data, offset, value)
        return data

    def mutate(self, data):
        strategies = [
            (self._mutate_elf_header, 0.20),
            (self._mutate_program_headers, 0.15),
            (self._mutate_section_headers, 0.15),
            (self._corrupt_string_table, 0.15),
            (self._create_nested_sections, 0.15),
            (self._integer_overflow_attack, 0.10),
            (self._bit_flip, 0.05),
            (self._byte_flip, 0.05),
        ]
        
        rand = random.random()
        cumulative = 0
        
        for strategy, weight in strategies:
            cumulative += weight
            if rand < cumulative:
                return strategy(data)
        
        return self._bit_flip(data)

    def _bit_flip(self, data):
        if len(data) == 0:
            return data
        result = bytearray(data)
        for _ in range(random.randint(1, 5)):
            idx = random.randint(0, len(result) - 1)
            bit = random.randint(0, 7)
            result[idx] ^= (1 << bit)
        return bytes(result)

    def _byte_flip(self, data):
        if len(data) == 0:
            return data
        result = bytearray(data)
        for _ in range(random.randint(1, 5)):
            idx = random.randint(0, len(result) - 1)
            result[idx] = random.randint(0, 255)
        return bytes(result)

    def fuzz(self, time_limit=60):
        print(f"Starting ELF fuzzer for {self.prog_name}")
        print(f"Binary: {self.binary_path}")
        print(f"Time limit: {time_limit} seconds")
        print("-" * 60)
        
        start_time = time.time()
        last_stats_time = start_time
        iteration = 0
        
        self.interesting_inputs.append(self.seed_input)
        
        while (time.time() - start_time) < time_limit:
            if self.interesting_inputs and random.random() < 0.9:
                base_input = random.choice(self.interesting_inputs)
            else:
                base_input = self.seed_input
            
            mutated = self.mutate(base_input)
            
            if len(mutated) > 100000:
                mutated = mutated[:100000]
            
            exit_code, signal_num, coverage_hash, exec_time = self._run_target(mutated)
            
            if self._is_crash(exit_code, signal_num):
                crash_type = f"CRASH (signal={signal_num}, exit={exit_code})"
                print(f"\n{crash_type} at iteration {iteration}")
                self._save_crash(mutated, crash_type)
            
            if coverage_hash and coverage_hash not in self.coverage_map:
                self.coverage_map.add(coverage_hash)
                if len(mutated) < 10000:
                    self.interesting_inputs.append(mutated)
            
            iteration += 1
            
            current_time = time.time()
            if current_time - last_stats_time >= 5:
                elapsed = current_time - start_time
                remaining = time_limit - elapsed
                execs_per_sec = self.total_executions / elapsed if elapsed > 0 else 0
                print(f"\rIter: {iteration:6d} | Execs: {self.total_executions:6d} | "
                      f"Speed: {execs_per_sec:6.1f}/s | Coverage: {len(self.coverage_map):4d} | "
                      f"Crashes: {self.crashes_found:3d} | Time: {elapsed:.1f}s/{time_limit}s", end='')
                last_stats_time = current_time
        
        elapsed_total = time.time() - start_time
        print(f"\n\nFuzzing completed in {elapsed_total:.2f} seconds")
        print(f"Total executions: {self.total_executions}")
        print(f"Crashes found: {self.crashes_found}")
        print(f"Coverage: {len(self.coverage_map)} unique paths")


def main():
    print("=" * 60)
    print("ELF Format Fuzzer (Docker Version) - elf1 Only")
    print("=" * 60)
    print()
    
    binaries_dir = "/binaries"
    example_inputs_dir = "/example_inputs"
    output_dir = "/fuzzer_output"
    
    os.makedirs(output_dir, exist_ok=True)
    
    binary_name = "elf1"
    binary_path = os.path.join(binaries_dir, binary_name)
    
    if not os.path.exists(binaries_dir):
        print(f"Binaries directory not found: {binaries_dir}")
        return
    
    print(f"Looking for target ELF binary: {binary_name}")
    print()
    
    if not (os.path.isfile(binary_path) and os.access(binary_path, os.X_OK)):
        print(f"Target binary not found or not executable: {binary_name}")
        print(f"Please ensure {binary_name} exists in {binaries_dir}")
        print(f"Run generate_vulnerable_elf.py first to create it")
        return
    
    print(f"Found target binary: {binary_name}")
    
    example_input = os.path.join(example_inputs_dir, f"{binary_name}.txt")
    if not os.path.exists(example_input):
        print(f"Input file not found: {binary_name}.txt")
        print(f"Will use generated minimal ELF as seed")
    else:
        print(f"Found input file: {binary_name}.txt")
    
    print()
    print(f"Time limit: 60 seconds")
    print()
    
    overall_start = time.time()
    
    # Fuzz elf1
    print(f"\n{'='*60}")
    print(f"Fuzzing: {binary_name}")
    print(f"{'='*60}\n")
    
    fuzzer = ELFFuzzer(binary_path, example_input, output_dir)
    
    try:
        fuzzer.fuzz(time_limit=60)
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    except Exception as e:
        print(f"\nError: {e}")
       
        traceback.print_exc()
    
    overall_elapsed = time.time() - overall_start
    
    print("\n" + "=" * 60)
    print(f"Fuzzing complete! Total time: {overall_elapsed:.2f}s")
    print("=" * 60)
    print()
    print("Results saved to /fuzzer_output/")
    print("Look for bad_elf1.txt")


if __name__ == "__main__":
    main()
