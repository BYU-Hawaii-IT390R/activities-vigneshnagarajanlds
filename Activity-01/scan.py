from pathlib import Path
import argparse

def scan_files_by_extension(directory, extension):
    directory = Path(directory)
    if not directory.exists():
        print("Directory does not exist.")
        return

    pattern = f"*.{extension.lstrip('.')}"
    files = list(directory.rglob(pattern))

    print(f"\nScanning: {directory.resolve()}")
    print(f"Found {len(files)} .{extension} files:\n")

    print(f"{'File':<40} {'Size (KB)':>10}")
    print("-" * 52)

    total_size = 0
    for file in files:
        size_kb = file.stat().st_size / 1024
        total_size += size_kb
        print(f"{str(file.relative_to(directory)):<40} {size_kb:>10.1f}")

    print("-" * 52)
    print(f"Total size: {total_size:.1f} KB\n")

if __name__ == "__main__
    parser = argparse.ArgumentParser(description="Recursively scan directory for files by extension.")
    parser.add_argument("path", help="Path to directory to scan")
    parser.add_argument("--ext", default="txt", help="File extension to scan for (default: txt)")
    args = parser.parse_args()
    scan_files_by_extension(args.path, args.ext)
