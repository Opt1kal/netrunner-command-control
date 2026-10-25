from rich.live import Live
from rich.panel import Panel
from rich.markup import escape
from rich.text import Text
from concurrent.futures import ThreadPoolExecutor
import time

from .animations import SignalWave
from .runtime import console

def format_execution_status(status: str) -> str:
    styles = {
        "waiting": "[dim white]· WAITING[/]",
        "running": "[nr.primary]◈ RUNNING[/]",
        "complete": "[nr.success]✓ COMPLETE[/]",
        "failed": "[nr.error]✗ FAILED[/]",
        "warning": "[nr.warning]! WARNING[/]",
    }

    return styles.get(
        status,
        f"[nr.text]{escape(status.upper())}[/]",
    )

class ExecutionActivity:
    def __init__(self, subject: str):
        self.subject = subject
        self.animation = SignalWave()
        self.live = Live(
            console=console,
            refresh_per_second=8,
            transient=True,
        )

    def __enter__(self):
        self.live.__enter__()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.live.__exit__(exc_type, exc_value, traceback)

    def update(self, progress=None):
        waveform = self.animation.next_frame()

        content = (
            f"[nr.primary]{waveform}[/]\n\n"
            "[nr.status]STATUS:[/] EXECUTING"
        )

        if progress is not None:
            content += (
                "\n\n"
                f"DNS LOOKUP      {format_execution_status(progress['dns'])}\n"
                f"PING            {format_execution_status(progress['ping'])}\n"
                f"ROUTE TRACE     {format_execution_status(progress['route'])}"
            )

        self.live.update(
            Panel(
                Text.from_markup(content, emoji=False),
                title=Text(self.subject, style="nr.primary"),
                border_style="nr.primary",
                expand=False,
            )
        )

def run_with_activity(
        subject,
        function,
        *args,
        progress_state=None,
        **kwargs,
        ):

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            function,
            *args,
            **kwargs,
        )

        with ExecutionActivity(subject) as activity:
            while not future.done():
                activity.update(progress_state)
                time.sleep(0.125)

    return future.result()
