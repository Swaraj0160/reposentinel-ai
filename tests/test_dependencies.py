"""Unit tests for dependency manifest and lockfile parsing."""

import json
from pathlib import Path
import pytest

from reposentinel.scanners.dependencies import (
    parse_package_json,
    parse_package_lock_json,
    parse_requirements_txt,
    parse_pyproject_toml,
    parse_poetry_lock,
    parse_pipfile_lock,
    collect_repository_dependencies,
)


def test_parse_package_json(tmp_path: Path):
    manifest = tmp_path / "package.json"
    manifest.write_text(
        json.dumps({
            "name": "sample",
            "dependencies": {
                "express": "^4.18.2",
                "lodash": "~4.17.21"
            },
            "devDependencies": {
                "jest": "29.5.0"
            }
        }),
        encoding="utf-8"
    )

    deps = parse_package_json(manifest)
    assert len(deps) == 3
    dep_dict = {d.name: d.version for d in deps}
    assert dep_dict["express"] == "4.18.2"
    assert dep_dict["lodash"] == "4.17.21"
    assert dep_dict["jest"] == "29.5.0"
    assert all(d.direct for d in deps)


def test_parse_package_lock_json_v3(tmp_path: Path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "dependencies": {"express": "^4.18.2"}
                },
                "node_modules/express": {
                    "version": "4.18.2"
                },
                "node_modules/qs": {
                    "version": "6.11.0"
                }
            }
        }),
        encoding="utf-8"
    )

    deps = parse_package_lock_json(lock)
    assert len(deps) == 2
    express_dep = next(d for d in deps if d.name == "express")
    qs_dep = next(d for d in deps if d.name == "qs")
    assert express_dep.direct is True
    assert qs_dep.direct is False


def test_parse_requirements_txt(tmp_path: Path):
    req_file = tmp_path / "requirements.txt"
    content = """
    # Primary application dependencies
    requests==2.31.0
    flask>=3.0.0; python_version >= '3.9'
    urllib3[socks]==2.0.7
    -r other-requirements.txt
    # Ignore git dependencies
    git+https://github.com/example/repo.git@v1.0
    """
    req_file.write_text(content, encoding="utf-8")

    deps = parse_requirements_txt(req_file)
    assert len(deps) == 3
    dep_names = {d.name for d in deps}
    assert dep_names == {"requests", "flask", "urllib3"}
    urllib_dep = next(d for d in deps if d.name == "urllib3")
    assert urllib_dep.version == "2.0.7"


def test_parse_pyproject_toml(tmp_path: Path):
    pyproject = tmp_path / "pyproject.toml"
    content = """
    [project]
    name = "my-project"
    dependencies = [
        "requests>=2.28.0",
        "fastapi==0.110.0",
    ]
    """
    pyproject.write_text(content, encoding="utf-8")

    deps = parse_pyproject_toml(pyproject)
    assert len(deps) == 2
    dep_map = {d.name: d.version for d in deps}
    assert dep_map["requests"] == "2.28.0"
    assert dep_map["fastapi"] == "0.110.0"


def test_parse_pipfile_lock(tmp_path: Path):
    pipfile = tmp_path / "Pipfile.lock"
    content = json.dumps({
        "default": {
            "pydantic": {"version": "==2.6.4"}
        },
        "develop": {
            "pytest": {"version": "==8.0.0"}
        }
    })
    pipfile.write_text(content, encoding="utf-8")

    deps = parse_pipfile_lock(pipfile)
    assert len(deps) == 2
    pydantic_dep = next(d for d in deps if d.name == "pydantic")
    assert pydantic_dep.version == "2.6.4"
    assert pydantic_dep.direct is True


def test_collect_repository_dependencies_deduplication(tmp_path: Path):
    # Manifest with range
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(json.dumps({"dependencies": {"lodash": "^4.17.0"}}), encoding="utf-8")

    # Lockfile with pinned exact version
    lock_json = tmp_path / "package-lock.json"
    lock_json.write_text(json.dumps({
        "packages": {
            "": {"dependencies": {"lodash": "^4.17.0"}},
            "node_modules/lodash": {"version": "4.17.21"}
        }
    }), encoding="utf-8")

    deps = collect_repository_dependencies(tmp_path)
    assert len(deps) == 1
    assert deps[0].name == "lodash"
    assert deps[0].version == "4.17.21"
    assert deps[0].direct is True
