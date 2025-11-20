import os
import subprocess
import sys
import json
import re
from pathlib import Path

BINARIES_DIR = "binaries"
INPUTS_DIR = "example_inputs"

FUZZER_PROGRAMS = {
    "json": [
        {
            "source": """
#include <stdio.h>
#include <string.h>

int depth = 0;

void parse(const char *s, int d) {
    char buf[16];  
    depth = d;
    sprintf(buf, "%d", d);  
    
    if (d < 100) {  
        for (const char *p = s; *p; p++) {
            if (*p == '{' || *p == '[') {
                parse(p + 1, d + 1); 
            }
        }
    }
}

int main() {
    char input[8192];
    size_t len = fread(input, 1, sizeof(input) - 1, stdin);
    input[len] = 0;
    parse(input, 0);
    return 0;
}
""",
            "input": json.dumps({"a": {"b": {"c": "test"}}}),
            "type": "text"
        },
        {
            "source": """
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void process(char *json, int level) {
    char stack_buf[32];
    sprintf(stack_buf, "lv%d", level);
    
    if (level < 50) {
        for (char *p = json; *p; p++) {
            if (*p == '{' || *p == '[') {
                process(p + 1, level + 1);
            }
        }
    }
    
    char value[8];
    char *colon = strchr(json, ':');
    if (colon && colon[1] == '"') {
        char *end = strchr(colon + 2, '"');
        if (end) {
            int len = end - colon - 2;
            memcpy(value, colon + 2, len);  
            value[len] = 0;
        }
    }
}

int main() {
    char *buf = malloc(16384);
    size_t n = fread(buf, 1, 16383, stdin);
    buf[n] = 0;
    process(buf, 0);
    free(buf);
    return 0;
}
""",
            "input": json.dumps({"x": "val", "y": [1, 2]}),
            "type": "text"
        }
    ],
    
    "xml": [
        {
            "source": """
#include <stdio.h>
#include <string.h>

int main() {
    char input[2048];
    char attr[32];  
    
    size_t len = fread(input, 1, sizeof(input) - 1, stdin);
    input[len] = 0;
    
    char *href = strstr(input, "href=\\"");
    if (href) {
        href += 6;
        char *end = strchr(href, '"');
        if (end) {
            size_t n = end - href;
            if (n < sizeof(attr)) {
                memcpy(attr, href, n);
                attr[n] = 0;
                printf(attr);  
                printf("\\n");
            }
        }
    }
    
    char text[16];  
    char *start = strstr(input, ">");
    if (start) {
        start++;
        char *end = strstr(start, "<");
        if (end) {
            memcpy(text, start, end - start);  
        }
    }
    
    return 0;
}
""",
            "input": '<?xml version="1.0"?><root><link href="test">X</link></root>',
            "type": "text"
        }
    ],
    
    "plaintext": [
        {
            "source": """
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main() {
    char line[512];
    char output[16];  
    
    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\\n")] = 0;
        
        strcpy(output, line);  

        if (strchr(line, '%')) {
            printf(line); 
            printf("\\n");
        }
      
        if (strncmp(line, "REP:", 4) == 0) {
            int count = atoi(line + 4);
            size_t alloc_size = count * 8;  
            
            if (alloc_size > 0) {
                char *buf = malloc(alloc_size);
                if (buf) {
                    for (int i = 0; i < count * 8; i++) {
                        buf[i] = 'X';
                    }
                    free(buf);
                }
            }
        }
      
        if (strncmp(line, "COPY:", 5) == 0) {
            char stack[8];
            strcpy(stack, line + 5);  
        }
    }
    return 0;
}
""",
            "input": "Hello\nTest\n",
            "type": "text"
        }
    ]
}

def compile_program(name, source_code, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    
    source_file = f"/tmp/{name}.c"
    binary_path = os.path.join(output_dir, name)
    
    with open(source_file, 'w') as f:
        f.write(source_code)
    
    compile_cmd = [
        "gcc",
        "-o", binary_path,
        source_file,
        "-O0",
        "-g",
        "-fno-stack-protector", 
        "-z", "execstack",        
        "-no-pie",
        "-fno-pie",
        "-Wno-format-security",
        "-Wno-implicit-function-declaration",
        "-D_FORTIFY_SOURCE=0",
        "-U_FORTIFY_SOURCE",
    ]
    
    try:
        result = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print(f"Compiled {name}")
            os.chmod(binary_path, 0o755)
            os.remove(source_file)
            return True
        else:
            print(f"Failed to compile {name}")
            print(f"stderr: {result.stderr}")
            return False
    except Exception as e:
        print(f"Error compiling {name}: {e}")
        return False

def find_max_number_for_type(type_prefix, directory):
    max_num = 0
    pattern = re.compile(rf'^{type_prefix}(\d+)$')
    
    if os.path.exists(directory):
        for filename in os.listdir(directory):
            if directory == INPUTS_DIR:
                filename = os.path.splitext(filename)[0]
            
            match = pattern.match(filename)
            if match:
                num = int(match.group(1))
                max_num = max(max_num, num)
    
    return max_num

def main():    
    try:
        subprocess.run(['gcc', '--version'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: gcc not found. Install with:")
        print("  sudo apt-get install build-essential")
        sys.exit(1)
    
    os.makedirs(BINARIES_DIR, exist_ok=True)
    os.makedirs(INPUTS_DIR, exist_ok=True)
   
    existing_counts = {}
    for type_name in FUZZER_PROGRAMS.keys():
        max_num = find_max_number_for_type(type_name, BINARIES_DIR)
        existing_counts[type_name] = max_num
     
    print()
    print("Generating vulnerable programs")
    print()
    
    created = 0
    failed = 0
    
    for type_name, templates in sorted(FUZZER_PROGRAMS.items()):
        start_num = existing_counts[type_name] + 1
        
        for idx, template in enumerate(templates):
            new_num = start_num + idx
            name = f"{type_name}{new_num}"
            
            print(f"{name}:")
            
            if compile_program(name, template["source"], BINARIES_DIR):
                input_file = os.path.join(INPUTS_DIR, f"{name}.txt")
                
                if template["type"] == "binary":
                    with open(input_file, 'wb') as f:
                        f.write(template["input"])
                else:
                    with open(input_file, 'w') as f:
                        f.write(template["input"])
                
                print(f"Created {name}.txt")
                created += 1
            else:
                failed += 1
            
            print()
  
    print("=" * 70)
    print("Summary:")
    print(f"  Created: {created} programs")
    print(f"  Failed:  {failed}")
    print("=" * 70)
    print()
    
    if created > 0:
        print("All programs generated successfully")
        print()
        

if __name__ == "__main__":
    main()
