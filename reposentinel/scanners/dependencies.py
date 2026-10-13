"""Multi-format dependency manifest and lockfile parser for npm and Python."""

import json
import re
from pathlib import Path
from typing import List, Dict, Any, Set, Tuple

from reposentinel.core.models import Dependency


def clean_version(raw_version: str) -> str:
    """Strips leading version operator prefixes like ^, ~, >=, ==, v."""
    v = raw_version.strip()
    v = re.sub(r"^[=~^><v\s]+", "", v)
    # Strip any trailing markers or comments
    v = v.split(";")[0].split()[0] if v else ""
    return v.strip()


def parse_package_json(path: Path) -> List[Dependency]:
    """Parses npm package.json manifests for direct dependencies."""
    deps: List[Dependency] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return deps

    sections = [
        ("dependencies", True),
        ("devDependencies", True),
        ("optionalDependencies", True),
        ("peerDependencies", True),
    ]

    for section, is_direct in sections:
        items = data.get(section, {})
        if isinstance(items, dict):
            for name, ver in items.items():
                if isinstance(ver, str):
                    cleaned = clean_version(ver)
                    if cleaned:
                        deps.append(
                            Dependency(
                                name=name,
                                version=cleaned,
                                ecosystem="npm",
                                source="package.json",
                                direct=is_direct,
                            )
                        )
    return deps


def parse_package_lock_json(path: Path) -> List[Dependency]:
    """
    Parses npm package-lock.json supporting versions 1, 2, and 3.
    Extracts installed transitive and direct packages.
    """
    deps: List[Dependency] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return deps

    # Lockfile v2 / v3 uses "packages"
    if "packages" in data and isinstance(data["packages"], dict):
        packages_dict = data["packages"]
        root_package = packages_dict.get("", {})
        direct_dep_names: Set[str] = set()
        for sec in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            direct_dep_names.update(root_package.get(sec, {}).keys())

        for pkg_key, pkg_info in packages_dict.items():
            if not pkg_key or not isinstance(pkg_info, dict):
                continue
            # Look for node_modules/<name>
            if "node_modules/" in pkg_key:
                # Get the last package name in case of nested node_modules
                parts = pkg_key.split("node_modules/")
                name = parts[-1]
                version = pkg_info.get("version")
                if name and version:
                    is_direct = name in direct_dep_names
                    deps.append(
                        Dependency(
                            name=name,
                            version=str(version),
                            ecosystem="npm",
                            source="package-lock.json",
                            direct=is_direct,
                        )
                    )

    # Lockfile v1 uses "dependencies" recursively
    elif "dependencies" in data and isinstance(data["dependencies"], dict):
        def walk_v1(deps_dict: Dict[str, Any], direct_level: bool):
            for name, info in deps_dict.items():
                if not isinstance(info, dict):
                    continue
                version = info.get("version")
                if version:
                    deps.append(
                        Dependency(
                            name=name,
                            version=str(version),
                            ecosystem="npm",
                            source="package-lock.json",
                            direct=direct_level,
                        )
                    )
                if "dependencies" in info and isinstance(info["dependencies"], dict):
                    walk_v1(info["dependencies"], False)

        walk_v1(data["dependencies"], True)

    return deps


def parse_requirements_txt(path: Path) -> List[Dependency]:
    """
    Parses Python requirements.txt files.
    Handles version specifiers, extras [security], environment markers, and options.
    """
    deps: List[Dependency] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return deps

    req_pattern = re.compile(
        r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]+\])?\s*(?:==|~=|>=|<=|>|<|===)\s*([A-Za-z0-9_.+!\-]+)"
    )

    for line in lines:
        line = line.strip()
        # Ignore comments and pip options
        if not line or line.startswith("#") or line.startswith(("-", "git+", "http://", "https://", "svn+", "hg+")):
            continue
        # Remove trailing inline comment
        if " #" in line:
            line = line.split(" #")[0].strip()
        # Remove environment markers
        if ";" in line:
            line = line.split(";")[0].strip()

        match = req_pattern.match(line)
        if match:
            pkg_name = match.group(1).strip()
            pkg_version = clean_version(match.group(2))
            if pkg_name and pkg_version:
                deps.append(
                    Dependency(
                        name=pkg_name,
                        version=pkg_version,
                        ecosystem="PyPI",
                        source="requirements.txt",
                        direct=True,
                    )
                )
    return deps


def parse_pyproject_toml(path: Path) -> List[Dependency]:
    """Parses pyproject.toml for PEP 621 dependencies or Poetry dependencies."""
    deps: List[Dependency] = []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return deps

    # Try standard tomllib / tomli if available, otherwise regex fallback
    data = None
    try:
        import tomllib  # Python 3.11+
        data = tomllib.loads(content)
    except Exception:
        try:
            import toml
            data = toml.loads(content)
        except Exception:
            pass

    if data:
        # 1. PEP 621 [project.dependencies]
        pep621_deps = data.get("project", {}).get("dependencies", [])
        if isinstance(pep621_deps, list):
            for entry in pep621_deps:
                match = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]+\])?\s*(?:==|~=|>=|<=|>|<)\s*([A-Za-z0-9_.+!\-]+)", str(entry))
                if match:
                    deps.append(
                        Dependency(
                            name=match.group(1),
                            version=clean_version(match.group(2)),
                            ecosystem="PyPI",
                            source="pyproject.toml",
                            direct=True,
                        )
                    )

        # 2. Poetry [tool.poetry.dependencies]
        poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
        if isinstance(poetry_deps, dict):
            for name, ver_val in poetry_deps.items():
                if name.lower() == "python":
                    continue
                version_str = ""
                if isinstance(ver_val, str):
                    version_str = ver_val
                elif isinstance(ver_val, dict) and "version" in ver_val:
                    version_str = str(ver_val["version"])
                cleaned = clean_version(version_str)
                if cleaned:
                    deps.append(
                        Dependency(
                            name=name,
                            version=cleaned,
                            ecosystem="PyPI",
                            source="pyproject.toml (poetry)",
                            direct=True,
                        )
                    )
    else:
        # Regex fallback for PEP 621 lines inside dependencies = [ ... ]
        dep_lines = re.findall(r'["\']([A-Za-z0-9_.\-]+)(?:\[[^\]]+\])?\s*(?:==|~=|>=|<=|>|<)\s*([A-Za-z0-9_.+!\-]+)["\']', content)
        for name, ver in dep_lines:
            deps.append(
                Dependency(
                    name=name,
                    version=clean_version(ver),
                    ecosystem="PyPI",
                    source="pyproject.toml",
                    direct=True,
                )
            )

    return deps


def parse_poetry_lock(path: Path) -> List[Dependency]:
    """Parses poetry.lock files for locked Python dependencies."""
    deps: List[Dependency] = []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return deps

    # Look for [[package]] blocks
    packages = re.findall(
        r'\[\[package\]\]\s*\n(?:[^\n]*\n)*?name\s*=\s*["\']([^"\']+)["\']\s*\n(?:[^\n]*\n)*?version\s*=\s*["\']([^"\']+)["\']',
        content,
    )
    for name, version in packages:
        deps.append(
            Dependency(
                name=name,
                version=version,
                ecosystem="PyPI",
                source="poetry.lock",
                direct=False,
            )
        )
    return deps


def parse_pipfile_lock(path: Path) -> List[Dependency]:
    """Parses Pipfile.lock for locked dependencies."""
    deps: List[Dependency] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return deps

    for section in ("default", "develop"):
        for name, info in data.get(section, {}).items():
            if isinstance(info, dict):
                ver = info.get("version", "")
                cleaned = clean_version(ver)
                if cleaned:
                    deps.append(
                        Dependency(
                            name=name,
                            version=cleaned,
                            ecosystem="PyPI",
                            source="Pipfile.lock",
                            direct=(section == "default"),
                        )
                    )
    return deps


def collect_repository_dependencies(root: Path) -> List[Dependency]:
    """
    Discovers and parses all dependency manifests and lockfiles across the repository.
    Merges duplicate dependencies, giving precedence to exact lockfile versions.
    """
    raw_deps: List[Dependency] = []

    # npm
    for pkg_json in root.rglob("package.json"):
        if "node_modules" not in pkg_json.parts and ".git" not in pkg_json.parts:
            raw_deps.extend(parse_package_json(pkg_json))

    for lock_json in root.rglob("package-lock.json"):
        if "node_modules" not in lock_json.parts and ".git" not in lock_json.parts:
            raw_deps.extend(parse_package_lock_json(lock_json))

    # Python
    for req_txt in root.rglob("*requirements*.txt"):
        if ".venv" not in req_txt.parts and "venv" not in req_txt.parts and ".git" not in req_txt.parts:
            raw_deps.extend(parse_requirements_txt(req_txt))

    for pyproj in root.rglob("pyproject.toml"):
        if ".venv" not in pyproj.parts and ".git" not in pyproj.parts:
            raw_deps.extend(parse_pyproject_toml(pyproj))

    for plock in root.rglob("poetry.lock"):
        if ".venv" not in plock.parts and ".git" not in plock.parts:
            raw_deps.extend(parse_poetry_lock(plock))

    for pip_lock in root.rglob("Pipfile.lock"):
        if ".venv" not in pip_lock.parts and ".git" not in pip_lock.parts:
            raw_deps.extend(parse_pipfile_lock(pip_lock))

    # Deduplicate dependencies
    # Preference rule: lockfile entries provide the exact version, but preserve direct flag if present in manifest
    dedup_map: Dict[Tuple[str, str], Dependency] = {}

    for dep in raw_deps:
        key = (dep.ecosystem.lower(), dep.name.lower())
        if key not in dedup_map:
            dedup_map[key] = dep
        else:
            existing = dedup_map[key]
            # If current is lockfile and existing is manifest, prefer lockfile version but retain direct if existing was direct
            if "lock" in dep.source.lower() and "lock" not in existing.source.lower():
                was_direct = existing.direct
                dep.direct = was_direct or dep.direct
                dedup_map[key] = dep
            elif existing.direct is False and dep.direct is True:
                existing.direct = True

    return list(dedup_map.values())
