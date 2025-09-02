import os
import sys
from heuristics import has_suspicious_apis, has_suspicious_python, calculate_entropy
from datetime import datetime
from heuristics import analyze_pe_structure


def load_signatures(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def scan_file(filepath, signatures):
    results = {
        "path": filepath,
        "matched_signature": None,
        "suspicious_api": None,
        "suspicious_import": None,
        "entropy": None,
        "pe_packed": None,
        "pe_imports": []
    }

    try:
        with open(filepath, 'rb') as f:
            raw_data = f.read()
            text = raw_data.decode(errors='ignore').lower()

            # Signature match
            for sig in signatures:
                if sig.lower() in text:
                    results["matched_signature"] = sig
                    break

            # Heuristics
            api_flag, api_keyword = has_suspicious_apis(text)
            if api_flag:
                results["suspicious_api"] = api_keyword

            py_flag, py_keyword = has_suspicious_python(text)
            if py_flag:
                results["suspicious_import"] = py_keyword

            # Entropy
            entropy = calculate_entropy(raw_data)
            results["entropy"] = round(entropy, 2)

            if filepath.lower().endswith(('.exe', '.dll')):
                pe_info = analyze_pe_structure(filepath)
                results["pe_packed"] = pe_info["packed"]
                results["pe_imports"] = pe_info["suspicious_imports"]


    except (PermissionError, FileNotFoundError, OSError) as e:
        print(f"[-] Skipped {filepath} (reason: {e})")
        return None

    return results

def scan_directory(directory, signatures):
    detections = []

    for root, dirs, files in os.walk(directory):
        for file in files:
            path = os.path.join(root, file)
            result = scan_file(path, signatures)
            if result:
                score = 0
                reasons = []

                if result["matched_signature"]:
                    score += 40
                    reasons.append(f"Signature: {result['matched_signature']}")

                if result["suspicious_api"]:
                    score += 30
                    reasons.append(f"API: {result['suspicious_api']}")

                if result["suspicious_import"]:
                    score += 20
                    reasons.append(f"Import: {result['suspicious_import']}")

                if result["entropy"] and result["entropy"] > 7.5:
                    score += 10
                    reasons.append(f"High Entropy: {result['entropy']}")

                if result["pe_imports"]:
                    score += 25
                    reasons.append(f"Suspicious PE imports: {', '.join(result['pe_imports'])}")

                if result["pe_packed"]:
                    score += 10
                    reasons.append("Packed with UPX or similar")

                if score >= 40:
                    print(f"[!] Suspicious file detected: {result['path']}")
                    print(f"    > Risk Score: {score}/100")
                    print(f"    > Reasons: {', '.join(reasons)}\n")

                    detections.append({
                        "path": result["path"],
                        "score": score,
                        "reasons": reasons
                    })

    return detections

def write_report(results):
    if not results:
        print("[*] No suspicious files found.")
        return

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"scan_report_{timestamp}.txt"
    
    with open(filename, "w", encoding="utf-8") as report:
        report.write(f"Scan Report - {timestamp}\n")
        report.write("=" * 40 + "\n\n")

        for result in results:
            report.write(f"[!] Suspicious file: {result['path']}\n")
            report.write(f"    > Risk Score: {result['score']}\n")
            report.write(f"    > Reasons: {', '.join(result['reasons'])}\n\n")

        report.write("=" * 40 + "\n")
        report.write(f"Scan Complete: {len(results)} suspicious file(s) found.\n")

    print(f"\n[✔] Scan complete. Report saved to: {filename}")

if __name__ == "__main__":
    # Determine base path (support for PyInstaller)
    def get_resource_path(relative_path):
        if hasattr(sys, '_MEIPASS'):
            return os.path.join(sys._MEIPASS, relative_path)
        return os.path.join(os.path.abspath("."), relative_path)

    # Load signatures with portable path
    sigs = load_signatures(get_resource_path("signatures/suspicious_strings.txt"))
    results = scan_directory(r"C:/Users/ASUS/Desktop/scanner-test", sigs)
    write_report(results)
