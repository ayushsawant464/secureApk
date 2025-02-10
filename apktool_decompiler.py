import subprocess

def decompile_apk(apk_path, output_dir):
    """Decompiles an APK using apktool."""
    print("---- Decompiling APK...")
    command = ["apktool", "d", apk_path, "-o", output_dir]
    subprocess.run(command, check=True)
    print("--- Decompilation completed.")
