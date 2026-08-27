from dataclasses import dataclass
import subprocess

@dataclass
class CommandRequest:
    program: str
    arguments: list[str]
    description: str

@dataclass
class CommandResult:
    request: CommandRequest
    stdout: str
    stderr: str
    exit_code: int

def run_command(request: CommandRequest) -> CommandResult:
    command = [request.program, *request.arguments]
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )
    return CommandResult(
        request=request,
        stdout=completed.stdout,
        stderr=completed.stderr,
        exit_code=completed.returncode,
    )

request = CommandRequest(
    program="ping",
    arguments=["-c", "5", "google.com"],
    description="( . Y . )",
)

result = run_command(request)

print(request.program)
print(request.arguments)
print(request.description)

print(result.stdout)
print(result.stderr)
print(result.exit_code)