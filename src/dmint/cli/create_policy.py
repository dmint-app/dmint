"""Interactive multi-turn wizard to create and validate Dmint policy files."""

from __future__ import annotations

import argparse
import ast
import getpass
import json
import sys
import questionary
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from dmint.policy import Policy, PolicyError
from dmint.cli.api import OpenAICompatClient, resolve_api_key
from dmint.cli.errors import (
    APIError,
    CLIError,
    InputFileError,
    JSONExtractionError,
    OutputWriteError,
    PolicyValidationError,
)
from dmint.cli.io_utils import atomic_write_json, atomic_write_policy_json, load_system_prompt
from dmint.cli.verify_policy import verify_policy_file


def parse_tool_declarations_ast(file_path: Path) -> list[dict[str, str]]:
    """Safe AST-based inspection of Python source file to discover tool names and descriptions.

    NO code execution (eval, exec, import) is performed.
    """
    if not file_path.exists():
        raise FileNotFoundError(f"tool source file not found: {file_path}")

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(content, filename=str(file_path))
    except Exception as exc:
        raise ValueError(f"failed to parse AST for {file_path}: {exc}") from exc

    discovered: list[dict[str, str]] = []
    seen: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr

            if func_name in {"Tool", "MCPToolBinding"}:
                tool_name = ""
                description = ""
                for kw in node.keywords:
                    if (
                        kw.arg in {"name", "tool_name"}
                        and isinstance(kw.value, ast.Constant)
                        and isinstance(kw.value.value, str)
                    ):
                        tool_name = kw.value.value
                    elif (
                        kw.arg == "description"
                        and isinstance(kw.value, ast.Constant)
                        and isinstance(kw.value.value, str)
                    ):
                        description = kw.value.value

                if not tool_name and node.args:
                    first_arg = node.args[0]
                    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                        tool_name = first_arg.value

                if tool_name and tool_name not in seen:
                    seen.add(tool_name)
                    discovered.append(
                        {
                            "name": tool_name,
                            "description": description or f"Discovered tool from {file_path.name}",
                            "source": file_path.name,
                        }
                    )

    return discovered


def discover_local_tools_ast(paths: list[Path | str]) -> list[dict[str, str]]:
    """Safely inspect multiple file/directory paths for tool declarations using static AST parsing."""
    discovered: list[dict[str, str]] = []
    seen: set[str] = set()

    file_paths: list[Path] = []
    for p_raw in paths:
        p = Path(p_raw).resolve()
        if not p.exists():
            print(f"[!] Warning: Path does not exist: {p}", file=sys.stderr)
            continue
        if p.is_file():
            if p.suffix == ".py":
                file_paths.append(p)
        elif p.is_dir():
            file_paths.extend(sorted(p.glob("**/*.py")))

    for f_path in file_paths:
        try:
            tools = parse_tool_declarations_ast(f_path)
            for t in tools:
                key = f"{f_path.name}:{t['name']}"
                if key not in seen:
                    seen.add(key)
                    discovered.append(t)
        except Exception as exc:
            print(f"[!] Warning: Could not parse AST for {f_path.name}: {exc}", file=sys.stderr)

    return discovered


def _prompt_select(message: str, choices: list[str], default: str) -> str:
    try:
        import questionary

        res = questionary.select(message, choices=choices, default=default).ask()
        if res is not None:
            return str(res)
    except Exception:
        pass
    print(f"\n{message}:")
    for idx, c in enumerate(choices, 1):
        print(f"  {idx}) {c}")
    val = input(f"Select [1-{len(choices)}, default: {default}]: ").strip()
    if val.isdigit() and 1 <= int(val) <= len(choices):
        return choices[int(val) - 1]
    return val or default


def _prompt_password(message: str) -> str:
    try:
        import questionary

        res = questionary.password(message).ask()
        if res is not None:
            return str(res)
    except Exception:
        pass
    return getpass.getpass(f"{message} ").strip()


def _prompt_text(message: str, default: str = "") -> str:
    try:
        import questionary

        res = questionary.text(message, default=default).ask()
        if res is not None:
            return str(res)
    except Exception:
        pass
    val = input(f"{message} [default: {default}]: ").strip()
    return val or default


def run_create_policy_wizard(
    *,
    access_md_file: str | Path,
    output_json_file: str | Path,
    tools_file: str | Path | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
    model: str | None = None,
    provider: str | None = None,
    non_interactive: bool = False,
    auto_confirm: bool = False,
    timeout: float = 60.0,
) -> Policy:
    """Multi-turn wizard for creating and verifying a Dmint policy file."""
    md_path = Path(access_md_file).resolve()
    json_path = Path(output_json_file).resolve()

    if not md_path.exists():
        raise InputFileError(f"input policy file not found: {md_path}")

    try:
        policy_text = md_path.read_text(encoding="utf-8").strip()
    except Exception as exc:
        raise InputFileError(f"failed to read input file: {exc}") from exc

    if not policy_text:
        raise InputFileError(f"input policy file is empty: {md_path}")

    if len(policy_text.encode("utf-8")) > 64 * 1024:
        raise InputFileError("input policy file exceeds 64KB size limit")

    is_tty = sys.stdin.isatty() and not non_interactive

    print("==================================================")
    print("      Dmint Interactive Policy Creation Wizard     ")
    print("==================================================")

    # Mode selection prompt when running interactively without explicit mode flags
    if is_tty and not tools_file:
        print("What are you protecting?\n")
        print("  1. External MCP server")
        print("  2. Local tools/source\n")
        mode_choice = input("Select mode [1/2, default 2]: ").strip()
        if mode_choice == "1":
            from dmint.cli.create_mcp_policy import run_create_mcp_policy_wizard

            policy, _ = run_create_mcp_policy_wizard(
                access_md_file=access_md_file,
                output_json_file=output_json_file,
                base_url=base_url,
                api_key=api_key,
                model=model,
                provider=provider,
                non_interactive=non_interactive,
                auto_confirm=auto_confirm,
                timeout=timeout,
            )
            return policy

        # Mode 2: Prompt for source paths (file(s) or directory(ies))
        src_path_in = input("Enter source file(s) or directory path(s) [e.g. tools/ or main.py, utils.py]: ").strip()
        if src_path_in:
            raw_paths: list[Path | str] = [p.strip() for p in src_path_in.split(",") if p.strip()]
            src_tools = discover_local_tools_ast(raw_paths)
            if src_tools:
                tools_summary = "\n".join(f"- {t['name']}: {t['description']}" for t in src_tools)
                policy_text = f"[DISCOVERED TOOL DECLARATIONS VIA AST]\n{tools_summary}\n\n[HUMAN SECURITY REQUIREMENTS]\n{policy_text}"

    discovered_tools: list[dict[str, str]] = []
    if tools_file:
        t_path = Path(tools_file).resolve()
        discovered_tools = parse_tool_declarations_ast(t_path)
        if discovered_tools:
            tools_summary = "\n".join(f"- {t['name']}: {t['description']}" for t in discovered_tools)
            policy_text = f"[DISCOVERED TOOL DECLARATIONS VIA AST IN {Path(tools_file).name}]\n{tools_summary}\n\n[HUMAN SECURITY REQUIREMENTS]\n{policy_text}"

    # 1. Provider & Key setup
    selected_provider = (provider or "").lower().strip()
    if is_tty and not selected_provider:
        selected_provider = _prompt_select(
            "Select provider", ["openai", "gemini", "groq", "openrouter", "ollama", "custom"], "openai"
        )
    elif not selected_provider:
        selected_provider = "openai"

    resolved_key = resolve_api_key(api_key, selected_provider)
    if is_tty and not resolved_key and selected_provider != "ollama":
        key_in = _prompt_password(f"Enter API Key for {selected_provider} (leave blank if using env var):")
        if key_in:
            resolved_key = key_in
            api_key = key_in

    # 2. Model Discovery & Selection
    client = OpenAICompatClient(
        base_url=base_url,
        api_key=resolved_key,
        model=model,
        provider=selected_provider,
        timeout=timeout,
    )

    selected_model = model
    if is_tty and not selected_model:
        try:
            available_models = client.list_models()
            default_model = (
                "gpt-4o-mini"
                if "gpt-4o-mini" in available_models
                else (available_models[0] if available_models else "gpt-4o-mini")
            )
            selected_model = _prompt_select(
                "Select model",
                available_models if available_models else ["gpt-4o-mini"],
                default_model,
            )
        except Exception as exc:
            print(f"\n[!] Could not list models: {exc}. Please enter model ID manually.")
            selected_model = _prompt_text("Enter model ID", "gpt-4o-mini")
    elif not selected_model:
        selected_model = "gpt-4o-mini"

    # Re-initialize client with selected model
    client = OpenAICompatClient(
        base_url=base_url,
        api_key=resolved_key,
        model=selected_model,
        provider=selected_provider,
        timeout=timeout,
    )

    print(f"\n[✓] Target model configured: {client.model} ({client.base_url})\n")

    # 3. Multi-turn conversation loop
    system_prompt = load_system_prompt()
    messages: list[Mapping[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": policy_text},
    ]

    shape_retry_attempts = 0
    policy_error_attempts = 0
    max_shape_retries = 3
    max_policy_error_retries = 4

    while True:
        try:
            raw_response = client.chat_completion(messages, temperature=0.0)
        except Exception as exc:
            raise APIError(str(exc)) from exc

        try:
            response_data = json.loads(raw_response)
        except json.JSONDecodeError:
            response_data = None

        # Check envelope shape
        if not isinstance(response_data, dict) or "type" not in response_data:
            shape_retry_attempts += 1
            if shape_retry_attempts >= max_shape_retries:
                raise JSONExtractionError(
                    f"Model failed to match output contract after {max_shape_retries} attempts. Raw response:\n{raw_response}"
                )
            messages.append({"role": "assistant", "content": raw_response})
            messages.append(
                {
                    "role": "user",
                    "content": "Your last response did not match the required output contract, resend as one of the two exact JSON shapes",
                }
            )
            continue

        msg_type = response_data.get("type")

        if msg_type == "clarification_needed":
            questions = response_data.get("questions")
            if not isinstance(questions, list) or not questions:
                questions = ["Could you clarify the resource scoping and trusted context for these rules?"]

            print("--- Clarification Needed from Assistant ---")
            answers: list[str] = []
            for idx, q in enumerate(questions, start=1):
                print(f"Q{idx}: {q}")
                if is_tty:
                    ans = input("A: ").strip()
                    answers.append(f"Q{idx}: {q}\nA{idx}: {ans if ans else 'No specific restriction.'}")
                else:
                    answers.append(f"Q{idx}: {q}\nA{idx}: Please apply default least-privilege rules for any resource.")

            messages.append({"role": "assistant", "content": json.dumps(response_data)})
            user_reply = "\n".join(answers)
            messages.append({"role": "user", "content": user_reply})
            print()
            continue

        elif msg_type == "policy_ready":
            rules = response_data.get("rules")
            if not isinstance(rules, list):
                shape_retry_attempts += 1
                if shape_retry_attempts >= max_shape_retries:
                    raise JSONExtractionError(f"policy_ready envelope missing 'rules' list. Raw:\n{raw_response}")
                messages.append({"role": "assistant", "content": raw_response})
                messages.append(
                    {
                        "role": "user",
                        "content": "Your last response did not match the required output contract, resend as one of the two exact JSON shapes",
                    }
                )
                continue

            policy_mapping = {"rules": rules}

            # Validate mapping with Dmint Policy engine & discovered tools
            try:
                from dmint.cli.create_mcp_policy import (
                    _assert_no_secrets_in_policy,
                    _validate_rule_completeness,
                    validate_policy_against_discovered_capabilities,
                )

                # Gate 1: completeness — every rule must have required fields.
                _validate_rule_completeness(rules)
                # Gate 2: no secrets in LLM-generated policy.
                _assert_no_secrets_in_policy(policy_mapping)
                if discovered_tools:
                    validate_policy_against_discovered_capabilities(policy_mapping, discovered_tools)

                verified_policy = Policy.from_mapping(policy_mapping)
            except (PolicyError, CLIError) as exc:
                policy_error_attempts += 1
                if policy_error_attempts >= max_policy_error_retries:
                    print(f"\n✗ Dmint policy validation failed: {exc}", file=sys.stderr)
                    print(f"Raw model response:\n{raw_response}", file=sys.stderr)
                    raise PolicyValidationError(
                        f"Dmint validation failed after {max_policy_error_retries} attempts: {exc}"
                    ) from exc

                messages.append({"role": "assistant", "content": json.dumps(response_data)})
                messages.append(
                    {
                        "role": "user",
                        "content": f"Dmint validation failed: {exc}. Fix it and resend.",
                    }
                )
                continue

            # Policy validation succeeded!
            print("--- Candidate Policy Review ---")
            print(f"Verified {len(verified_policy.rules)} rules:")
            for r in verified_policy.rules:
                res_str = r.resource if isinstance(r.resource, str) else type(r.resource).__name__
                print(f"  [{r.effect.value.upper()}] tool='{r.tool}', action='{r.action}', resource='{res_str}'")

            if not auto_confirm and is_tty:
                confirm = input("\nAccept candidate policy and write policy.json? [y/N]: ").strip().lower()
                if confirm not in ("y", "yes"):
                    raise CLIError("policy creation aborted by user", exit_code=1)

            # Serialize via Policy.to_dict() for canonical, deterministic output (not raw LLM dict).
            atomic_write_policy_json(json_path, verified_policy)

            # Final sanity check via verify_policy_file
            verify_policy_file(json_path)

            print(f"\n✓ Verified & saved: {json_path}\n")
            return verified_policy

        else:
            shape_retry_attempts += 1
            if shape_retry_attempts >= max_shape_retries:
                raise JSONExtractionError(
                    f"Model returned unrecognized response type '{msg_type}'. Raw response:\n{raw_response}"
                )
            messages.append({"role": "assistant", "content": raw_response})
            messages.append(
                {
                    "role": "user",
                    "content": "Your last response did not match the required output contract, resend as one of the two exact JSON shapes",
                }
            )
            continue


def main_create(args: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dmint create-policy",
        description="General policy authoring wizard: interactive multi-turn assistant to turn natural language requirements into verified Dmint policy files.",
    )
    parser.add_argument("-f", "--file", required=True, help="Input developer intent markdown file (e.g. access.md)")
    parser.add_argument("-o", "--output", required=True, help="Output verified policy JSON file (e.g. policy.json)")
    parser.add_argument("--tools", help="Optional path to tool source file (for compatibility)")
    parser.add_argument("-provider", "--provider", help="LLM provider (e.g. openai, gemini, groq, openrouter, ollama)")
    parser.add_argument(
        "-base_url", "--base-url", help="OpenAI-compatible base URL (default: https://api.openai.com/v1)"
    )
    parser.add_argument("-api_key", "--api-key", help="API key (or via OPENAI_API_KEY / GEMINI_API_KEY env vars)")
    parser.add_argument("-model", "--model", help="Model name (e.g. gpt-4o-mini, gemini-1.5-flash)")
    parser.add_argument("--non-interactive", action="store_true", help="Run without terminal input prompts")
    parser.add_argument("-y", "--yes", action="store_true", help="Auto-confirm candidate policy without prompting")
    parser.add_argument("--timeout", type=float, default=60.0, help="API request timeout in seconds (default: 60.0)")

    try:
        parsed = parser.parse_args(args)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 0

    try:
        run_create_policy_wizard(
            access_md_file=parsed.file,
            output_json_file=parsed.output,
            tools_file=parsed.tools,
            base_url=parsed.base_url,
            api_key=parsed.api_key,
            model=parsed.model,
            provider=parsed.provider,
            non_interactive=parsed.non_interactive,
            auto_confirm=parsed.yes,
            timeout=parsed.timeout,
        )
        return 0
    except CLIError as exc:
        print(f"✗ Policy creation failed: {exc}", file=sys.stderr)
        return exc.exit_code
    except Exception as exc:
        print(f"✗ Unexpected error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main_create())
