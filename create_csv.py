import os
import csv

# Output CSV file
output_file = "output.csv"

# Open the CSV file for writing
with open(output_file, mode="w", newline="") as csv_file:
    writer = csv.writer(csv_file)
    writer.writerow(["Index", "Code"])
    
    # Loop over the range 1 to 50
    for i in range(1, 51):
        filename = f"ebpf_programs/prog{i}.bpf.c"
        
        # Check if the file exists
        if os.path.exists(filename):
            with open(filename, "r", encoding="utf-8") as f:
                # Read file content and replace newlines with spaces
                code = " ".join(line.strip() for line in f)
                writer.writerow([i, code])
        else:
            print(f"Warning: {filename} not found, skipping.")

print(f"CSV file '{output_file}' created successfully.")
