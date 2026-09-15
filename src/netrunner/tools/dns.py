from dataclasses import dataclass
from ..core.models import CommandRequest, CommandResult

def build_dns_request(query: str, record_type: str) -> CommandRequest:
    """
    Build a CommandRequest for the dig command to perform a DNS lookup.

    Args:
        query (str): The domain name or IP address to query.
        record_type (str): The type of DNS record to query (e.g., "A", "AAAA", "MX", "CNAME", etc.).

    Returns:
        CommandRequest: A CommandRequest object for the dig command.
    """
    return CommandRequest(
        program="dig",
        arguments=[query, record_type],
        description=f"Perform a DNS lookup for {query} with record type {record_type}.",
    )

@dataclass
class DNSResult:
    """
    A dataclass to represent the result of a DNS lookup command.

    Attributes:
        query (str): The domain name or IP address that was queried.
        record_type (str): The type of DNS record that was queried.
        answers (list[str]): A list of answers returned by the DNS server.
        query_time (int | None): The time taken to perform the DNS query in milliseconds.
        server (str | None): The DNS server that provided the response.
        status (str): The status of the DNS lookup command (e.g., "success", "error", etc.).
    """
    query: str
    record_type: str
    answers: list[str]
    query_time: int | None
    server: str | None
    status: str

def parse_dns_result(result: CommandResult) -> DNSResult:
    """
    Parse the result of a DNS lookup command into a DNSResult object.

    Args:
        result (CommandResult): The result of the DNS lookup command.

    Returns:
        DNSResult: A DNSResult object containing parsed information from the DNS lookup command output.
    """
    lines = result.stdout.splitlines()
    query = result.request.arguments[0]
    record_type = result.request.arguments[1]
    answers = []
    query_time = None
    server = None

    dns_status = None
    status = None
    in_answer_section = False

    for line in lines:
        if line.startswith(";; ANSWER SECTION:"):
            in_answer_section = True
            # Start collecting answers
            continue
        elif in_answer_section and not line:
            # End of answer section
            in_answer_section = False
        elif line.startswith(";; Query time:"):
            query_time = int(line.split(":")[1].strip().split()[0])
        elif line.startswith(";; SERVER:"):
            server = line.split(":")[1].strip()
        elif line.startswith(";; ->>HEADER<<-"):
            dns_status = line.split("status: ")[1].split(",")[0].strip()
        elif in_answer_section:
            # Collect answer lines
            answers.append(line.strip().split()[-1])

    if dns_status is None:
        status = "error"
    elif dns_status == "NOERROR" and answers:
        status = "success"
    elif dns_status == "NOERROR" and not answers:
        status = "not_answered"
    elif dns_status == "NXDOMAIN":
        status = "not_found"
    else:
        status = "error"

    return DNSResult(
        query=query,
        record_type=record_type,
        answers=answers,
        query_time=query_time,
        server=server,
        status=status,
    )
