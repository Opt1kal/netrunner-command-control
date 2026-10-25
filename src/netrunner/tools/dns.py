from dataclasses import dataclass
from ipaddress import ip_address
import re
from ..core.models import CommandRequest, CommandResult


class InvalidDNSQuery(ValueError):
    """DNS input is not a supported query name or record type."""


def _query_name(query: str) -> str:
    if not query or any(character.isspace() or ord(character) < 32 for character in query):
        raise InvalidDNSQuery("Enter one DNS query name without whitespace or control characters.")
    if query == ".":
        return query

    try:
        # Preserve IP-literal queries; these are not automatic reverse lookups.
        ip_address(query)
    except ValueError:
        pass
    else:
        if "%" not in query:
            return query

    try:
        name = query.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidDNSQuery("The DNS query name could not be encoded as IDNA.") from exc

    labels = name.removesuffix(".").split(".")
    if (
        name.startswith(("-", "+", "@"))
        or len(name.removesuffix(".")) > 253
        or any(
            len(label) > 63 or re.fullmatch(r"[A-Za-z0-9_-]+|\*", label) is None
            for label in labels
        )
    ):
        raise InvalidDNSQuery(
            "Enter a DNS name, root (.), or IP literal; options, directives, lists, "
            "and escaped names are not supported."
        )
    return name


def _record_type(record_type: str) -> str:
    # Validate the argument syntax, leaving mnemonic support to the installed dig.
    # This avoids freezing a small allowlist as DNS record types evolve.
    if not record_type.isascii():
        raise InvalidDNSQuery("Enter a DNS record type such as A, AAAA, MX, or TYPE65.")
    value = record_type.upper()
    generic = re.fullmatch(r"TYPE([0-9]+)", value)
    incremental = re.fullmatch(r"IXFR=([0-9]+)", value)
    if value.startswith("TYPE"):
        valid = generic is not None and len(generic[1]) <= 5 and int(generic[1]) <= 65535
    elif incremental:
        valid = len(incremental[1]) <= 10 and int(incremental[1]) <= 4294967295
    else:
        valid = re.fullmatch(r"[A-Z][A-Z0-9-]*", value) is not None
    if not valid:
        raise InvalidDNSQuery("Enter one DNS record type, not an option, directive, or query name.")
    return value


def build_dns_request(query: str, record_type: str) -> CommandRequest:
    """
    Build a CommandRequest for the dig command to perform a DNS lookup.

    Args:
        query (str): The domain name or IP address to query.
        record_type (str): The type of DNS record to query (e.g., "A", "AAAA", "MX", "CNAME", etc.).

    Returns:
        CommandRequest: A CommandRequest object for the dig command.
    """
    query = _query_name(query)
    record_type = _record_type(record_type)
    return CommandRequest(
        program="dig",
        arguments=["-q", query, "-t", record_type],
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
    query = result.request.arguments[1]
    record_type = result.request.arguments[3]
    if result.exit_code != 0:
        return DNSResult(query, record_type, [], None, None, "error")
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
            server = line.split(":", 1)[1].strip()
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
