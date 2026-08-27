from .core.models import CommandRequest
from .core.runner import run_command

def main():
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