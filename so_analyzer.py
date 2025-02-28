import os
import subprocess
import re
import ahocorasick
from collections import defaultdict
import time

class SharedObjectAnalyzer:
    UNSAFE_FUNCTIONS = {"strcpy", "sprintf", "gets", "system", "exec", "strcat",
                        "popen", "execve", "setuid", "setgid", "getenv", "access"}

    FORMAT_STRING_PATTERNS = re.compile(r"%s|%n|%p")
    HARD_CODED_PATTERN = re.compile(r"(?P<URL>https?://[\w./-]+)|"
                                    r"(?P<IP>\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)|"
                                    r"(?P<FILE_PATH>/[^\s]+)")
        
    def __init__(self, directory):
        self.directory = directory
        self.so_files = self.find_so_files()
        self.trie = self.build_aho_corasick_trie()

    def find_so_files(self):
        """Find all .so files in the directory."""
        so_files = []
        for root, _, files in os.walk(self.directory):
            for file in files:
                if file.endswith(".so"):
                    so_files.append(os.path.join(root, file))
        return so_files
    
    def extract_strings(self, file_path):
        try:
            return subprocess.check_output(["strings", file_path], stderr=subprocess.DEVNULL).decode().split("\n")
        except Exception as e:
            print(f"[!] Error extracting strings from {file_path}: {e}")
            return []
    
    def run_check(self, command, file_path, error_message, keyword=None):
        try:
            output = subprocess.check_output(command, stderr=subprocess.DEVNULL).decode()
            if keyword and keyword in output:
                print(f"[⚠] {error_message}: {file_path}")
        except Exception as e:
            print(f"[!] Error: {error_message}: {e}")
    
    def check_stack_protection(self, file_path):
        self.run_check(["checksec", "--fortify", file_path], file_path, "Stack protection not enabled", keyword="No")
    
    def check_rop_gadgets(self, file_path):
        self.run_check(["ROPgadget", "--binary", file_path], file_path, "ROP Gadgets detected", keyword="gadgets found")
    
    def check_format_string(self, file_path, strings):
        matches = [(i+1, line) for i, line in enumerate(strings) if self.FORMAT_STRING_PATTERNS.search(line)]
        self.print_findings("Format string vulnerabilities detected", matches, file_path)
    
    def check_null_dereference(self, file_path, strings):
        matches = [(i+1, line) for i, line in enumerate(strings) if "NULL" in line or "nullptr" in line]
        self.print_findings("Possible NULL dereference vulnerabilities", matches, file_path)
    
    def check_hardcoded_links(self, file_path, strings):
        matches = [(i+1, match.group()) for i, line in enumerate(strings) for match in self.HARD_CODED_PATTERN.finditer(line)]
        self.print_findings("Hardcoded links found", matches, file_path)
    
    def check_insecure_functions(self, file_path, strings):
        matches = [(i+1, line) for i, line in enumerate(strings) if any(func in line for func in self.UNSAFE_FUNCTIONS)]
        self.print_findings("Usage of unsafe functions detected", matches, file_path)
    
    def check_path_manipulation(self, file_path, strings):
        matches = [(i+1, line) for i, line in enumerate(strings) if ".." in line or "/tmp" in line]
        self.print_findings("Potential path manipulation vulnerabilities", matches, file_path)
    
    def build_aho_corasick_trie(self):
        trie = ahocorasick.Automaton()
        sensitive_keywords = {"password", "secret", "key", "token", "api_key", "private"}
        for keyword in sensitive_keywords:
            trie.add_word(keyword.lower(), keyword)
        trie.make_automaton()
        return trie
    
    def check_data_leakage(self, file_path, strings):
        found_keywords = defaultdict(list)
        for i, line in enumerate(strings):
            for _, keyword in self.trie.iter(line.lower()):
                found_keywords[keyword].append((i+1, line.strip()))
        for keyword, matches in found_keywords.items():
            print(f"[⚠] Possible data leakage (`{keyword}`) detected in {file_path}:")
            for line_no, match in matches[:5]:
                print(f"    Line {line_no}: {match}")
    
    def print_findings(self, message, matches, file_path):
        if matches:
            print(f"[⚠] {message} in {file_path}:")
            for line_no, match in matches[:5]:
                print(f"    Line {line_no}: {match}")
    
    def analyze(self):
        start_time = time.time()
        if not self.so_files:
            print("[-] No .so files found.")
            return
        
        print(f"[+] Found {len(self.so_files)} .so files. Starting analysis...\n")
        for so_file in self.so_files:
            print(f"\n[+] Analyzing {so_file}...\n" + "-" * 50)
            strings = self.extract_strings(so_file)
            checks = [
                self.check_stack_protection,
                self.check_rop_gadgets,
                lambda f: self.check_format_string(f, strings),
                lambda f: self.check_null_dereference(f, strings),
                lambda f: self.check_hardcoded_links(f, strings),
                lambda f: self.check_insecure_functions(f, strings),
                lambda f: self.check_path_manipulation(f, strings),
                lambda f: self.check_data_leakage(f, strings),
            ]
            for check in checks:
                check(so_file)
            print("[+] Analysis complete.")
            print("-" * 50)
        print(f"[✔] Analysis finished in {time.time() - start_time:.2f} seconds.")

