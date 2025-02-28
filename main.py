import argparse
import time
from apktool_decompiler import decompile_apk
from vulnerability_scanner import VulnerabilityScanner
from so_analyzer import SharedObjectAnalyzer

def main():
    parser = argparse.ArgumentParser(description="Decompile an APK and search for vulnerabilities.")
    parser.add_argument("apk", help="Path to the APK file")
    parser.add_argument("output", help="Path to save the decompiled APK")
    args = parser.parse_args()

    start_time = time.time()  # Start timer

    print("[*] Decompiling APK...")
    decompile_apk(args.apk, args.output)
    
    print("[*] Searching for vulnerabilities...")
    smali_scanner = VulnerabilityScanner(args.output)
    smali_scanner.search_vulnerabilities()

    print("[*] Analyzing .so file...")
    analyzer = SharedObjectAnalyzer(args.output)
    analyzer.analyze()
    end_time = time.time()  # End timer

    elapsed_time = end_time - start_time  
    print(f"[*] Analysis completed in {elapsed_time:.2f} seconds.")

if __name__ == "__main__":
    main()
