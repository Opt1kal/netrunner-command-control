from dataclasses import dataclass


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