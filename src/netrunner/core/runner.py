import subprocess
from .models import CommandRequest, CommandResult


# Application wall-clock limits, in seconds, for the current tool requests.
# These are deliberately longer for route tracing and service discovery.
# Unknown programs retain the generic runner's unbounded behavior.
COMMAND_TIMEOUTS = {
    "ping": 60,
    "dig": 60,
    "traceroute": 600,
    "rustscan": 900,
    "nmap": 1800,
}


def _output_text(output: str | bytes | None) -> str:
    # TimeoutExpired may contain bytes even when subprocess.run uses text=True.
    if isinstance(output, bytes):
        return output.decode(errors="replace")
    return output or ""


def run_command(request: CommandRequest) -> CommandResult:
    command = [request.program, *request.arguments]
    timeout = COMMAND_TIMEOUTS.get(request.program)
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return CommandResult(
            request=request,
            stdout="",
            stderr=f"Required tool '{request.program}' was not found. Check that it is installed and on PATH.",
            exit_code=127,
        )
    except OSError as exc:
        # Includes PermissionError and invalid executable formats.
        return CommandResult(
            request=request,
            stdout="",
            stderr=f"Could not execute '{request.program}': {exc}",
            exit_code=126,
        )
    except subprocess.TimeoutExpired as exc:
        detail = _output_text(exc.stderr)
        message = f"Tool '{request.program}' exceeded its {timeout}-second execution deadline."
        return CommandResult(
            request=request,
            stdout=_output_text(exc.stdout),
            stderr=f"{detail.rstrip()}\n{message}" if detail else message,
            exit_code=124,
        )

    return CommandResult(
        request=request,
        stdout=completed.stdout,
        stderr=completed.stderr,
        exit_code=completed.returncode,
    )
