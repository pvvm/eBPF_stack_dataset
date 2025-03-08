import os
import sys
import subprocess

def compile_programs(mode):
    if mode not in ["default", "optimized"]:
        print("Invalid mode. Use 'default' or 'optimized'.")
        return
    
    output_dir = f"ebpf_programs/object/{mode}"
    os.makedirs(output_dir, exist_ok=True)
    
    for i in range(1, 51):
        source_file = f"ebpf_programs/prog{i}.bpf.c"
        object_file = f"{output_dir}/prog{i}.bpf.o"
        disassembly_file = f"{output_dir}/stack/prog{i}stack.txt"
        
        if not os.path.exists(source_file):
            print(f"Warning: {source_file} not found, skipping.")
            continue
        
        # Compile command
        clang_flags = "-O2 -g -Wall -target bpf" if mode == "optimized" else "-g -Wall -target bpf"
        compile_cmd = f"clang {clang_flags} -c {source_file} -o {object_file}"
        
        try:
            print(f"Compiling {source_file}...")
            subprocess.run(compile_cmd, shell=True, check=True)
            
            # Run llvm-objdump
            objdump_cmd = f"llvm-objdump -S {object_file} > {disassembly_file}"
            print(f"Generating disassembly for {object_file}...")
            subprocess.run(objdump_cmd, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error compiling {source_file}: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python compile_bpf.py <default|optimized>")
    else:
        compile_programs(sys.argv[1])
