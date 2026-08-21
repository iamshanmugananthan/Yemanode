"""Detects programming languages and project type present in a repository by file extension / markers."""
import os
from collections import Counter

EXT_MAP = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript",
    ".tsx": "TypeScript", ".java": "Java", ".go": "Go", ".rb": "Ruby", ".php": "PHP",
    ".c": "C", ".h": "C", ".cpp": "C++", ".hpp": "C++", ".cs": "C#", ".rs": "Rust",
    ".kt": "Kotlin", ".kts": "Kotlin", ".swift": "Swift", ".sh": "Shell", ".bash": "Shell",
    ".sql": "SQL", ".yaml": "YAML", ".yml": "YAML", ".tf": "Terraform", ".json": "JSON",
    ".html": "HTML", ".vue": "Vue", ".dart": "Dart", ".scala": "Scala", ".groovy": "Groovy",
    ".xml": "XML", ".plist": "Plist", ".gradle": "Gradle", ".properties": "Properties",
}

IGNORE_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build",
    ".next", "target", "vendor", ".idea", ".vscode", "coverage", ".gradle",
    "Pods", "DerivedData", ".dart_tool", "android/.gradle",
}

MANIFEST_NAMES = {
    "requirements.txt", "package.json", "pyproject.toml", "Pipfile",
    "go.mod", "Gemfile", "composer.json", "pom.xml", "build.gradle",
    "build.gradle.kts", "Cargo.toml", "pubspec.yaml", "Podfile",
    "AndroidManifest.xml", "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "terraform.tf", "main.tf", "serverless.yml", "template.yaml",
}


def scan_repo(repo_path: str):
    """Walk repo, return (language_counts, file_list, manifest_files_found)."""
    lang_counts = Counter()
    all_files = []
    manifests = []

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")]
        for f in files:
            full = os.path.join(root, f)
            all_files.append(full)
            if f in MANIFEST_NAMES or f.endswith((".tf", ".tfvars")):
                manifests.append(full)
            ext = os.path.splitext(f)[1].lower()
            if ext in EXT_MAP:
                lang_counts[EXT_MAP[ext]] += 1
            # Special cases
            if f == "AndroidManifest.xml":
                lang_counts["Android"] += 1
            if f.lower() == "dockerfile":
                lang_counts["Docker"] += 1

    return lang_counts, all_files, manifests


def primary_languages(lang_counts, top_n=8):
    return [lang for lang, _ in lang_counts.most_common(top_n)]


def detect_project_type(repo_path: str, manifests: list) -> str:
    """Heuristic project type for better reporting."""
    names = {os.path.basename(m).lower() for m in manifests}
    if "androidmanifest.xml" in names or any("android" in m.lower() for m in manifests):
        return "Android / Mobile"
    if "package.json" in names:
        return "Node.js / JavaScript"
    if "requirements.txt" in names or "pyproject.toml" in names or "pipfile" in names:
        return "Python"
    if "pom.xml" in names or "build.gradle" in names or "build.gradle.kts" in names:
        return "Java / JVM"
    if "go.mod" in names:
        return "Go"
    if "cargo.toml" in names:
        return "Rust"
    if "pubspec.yaml" in names:
        return "Flutter / Dart"
    if any(m.endswith((".tf", ".tfvars")) for m in manifests):
        return "Infrastructure (Terraform)"
    if "dockerfile" in names or "docker-compose.yml" in names:
        return "Containerized"
    return "Generic / Multi-language"
