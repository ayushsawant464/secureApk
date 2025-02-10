import argparse
from apktool_decompiler import decompile_apk
from vulnerability_scanner import search_vulnerabilities

def main():
    parser = argparse.ArgumentParser(description="Decompile an APK and search for vulnerabilities.")
    parser.add_argument("apk", help="Path to the APK file")
    parser.add_argument("output", help="Path to save the decompiled APK")
    args = parser.parse_args()
    
    decompile_apk(args.apk, args.output)
    search_vulnerabilities(args.output)

if __name__ == "__main__":
    main()
