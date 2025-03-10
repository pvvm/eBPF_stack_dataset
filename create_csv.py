import os
import csv

# Output CSV file
output_file = "output.csv"


def write_column(filename_bpf, filename_diagram, i):
    code = ""
    diagram = ""
    # Check if the file exists
    if os.path.exists(filename_bpf):
        with open(filename_bpf, "r", encoding="utf-8") as f:
            # Read file content and replace newlines with spaces
            code = " ".join(line.strip() for line in f)
    else:
        print(f"Warning: {filename_bpf} not found, skipping.")

    if os.path.exists(filename_diagram):
        with open(filename_diagram, "r", encoding="utf-8") as f:
            # Read file content and replace newlines with spaces
            diagram = " ".join(line.strip() for line in f)
            writer.writerow([i, code, diagram])
    else:
        print(f"Warning: {filename_diagram} not found, skipping.")

# Open the CSV file for writing
with open(output_file, mode="w", newline="") as csv_file:
    writer = csv.writer(csv_file)
    writer.writerow(["Index", "Code", "Diagram"])
    
    # Loop over the range 1 to 50
    for i in range(1, 51):
        write_column(f"ebpf_programs/prog{i}.bpf.c", f"mermaid_diagrams/default/prog{i}.txt", i)

print(f"CSV file '{output_file}' created successfully.")
