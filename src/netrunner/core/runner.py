import subprocess
from .models import CommandRequest, CommandResult

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