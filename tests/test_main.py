import unittest
from unittest.mock import ANY, call, patch, sentinel

from netrunner import main as cli


class ReconCliTests(unittest.TestCase):
    def test_recon_without_target_prompts_then_runs_with_entered_target(self):
        self.check_prompted_recon(["lab.example"])

    def test_recon_reprompts_after_empty_target(self):
        self.check_prompted_recon(["", "lab.example"])

    def check_prompted_recon(self, responses):
        with (
            patch("sys.argv", ["nrc", "recon"]),
            patch("subprocess.run", side_effect=AssertionError("Unexpected external command")),
            patch.object(cli, "prompt_input", side_effect=responses) as prompt,
            patch.object(cli, "run_target_recon", return_value=sentinel.recon_result) as recon,
            patch.object(cli, "run_with_activity") as activity,
            patch.object(cli, "show_header"),
            patch.object(cli, "show_error") as show_error,
            patch.object(cli, "show_recon_result") as show_result,
        ):
            # Keep CLI orchestration real; replace animation and networking only.
            activity.side_effect = lambda subject, function, *args, **kwargs: function(*args)
            cli.main()

        self.assertEqual(prompt.call_args_list, [call("TARGET")] * len(responses))
        self.assertEqual(
            show_error.call_args_list,
            [call("Target cannot be empty.")] * (len(responses) - 1),
        )
        recon.assert_called_once_with("lab.example", ANY)
        self.assertTrue(callable(recon.call_args.args[1]))
        activity.assert_called_once_with(
            "TARGET RECON",
            recon,
            "lab.example",
            ANY,
            progress_state={"dns": "waiting", "ping": "waiting", "route": "waiting"},
        )
        show_result.assert_called_once_with(sentinel.recon_result)
