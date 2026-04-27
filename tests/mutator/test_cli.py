import json
from importlib import import_module
import unittest
from typing import Any

from typer.testing import CliRunner

from volte_mutation_fuzzer.generator.cli import app as generator_app

REALISTIC_CALL_ID = "a84b4c76e66710@pcscf.ims.mnc001.mcc001.3gppnetwork.org"
REALISTIC_LOCAL_TAG = "9fxced76sl"


class SIPMutatorCLITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = CliRunner()
        module = import_module("volte_mutation_fuzzer.mutator.cli")
        cls.app = module.app

    def generate_request_baseline_json(self, method: str) -> str:
        result = self.runner.invoke(generator_app, ["request", method])

        self.assertEqual(result.exit_code, 0, msg=result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["method"], method)
        return result.stdout

    def parse_output(self, result) -> dict[str, Any]:
        self.assertEqual(result.exit_code, 0, msg=result.output)
        # ``mutate`` CLI now prefixes its JSON payload with a ``=== wire_text
        # ===`` block (rendered SIP message, LF separators) and a
        # ``=== change context ===`` block. The JSON-parseable section
        # starts after the ``=== mutation_result (json) ===`` marker.
        output = result.stdout
        marker = "=== mutation_result (json) ==="
        if marker in output:
            output = output.split(marker, 1)[1].strip()
        return json.loads(output)

    def test_packet_command_mutates_generator_cli_json_from_stdin(self) -> None:
        baseline_json = self.generate_request_baseline_json("OPTIONS")

        result = self.runner.invoke(
            self.app,
            [
                "packet",
                "--profile",
                "parser_breaker",
                "--layer",
                "wire",
                "--seed",
                "7",
                "--strategy",
                "final_crlf_loss",
            ],
            input=baseline_json,
        )

        payload = self.parse_output(result)

        self.assertEqual(payload["profile"], "parser_breaker")
        self.assertEqual(payload["final_layer"], "wire")
        self.assertEqual(payload["strategy"], "final_crlf_loss")
        self.assertEqual(payload["seed"], 7)
        self.assertEqual(payload["original_packet"]["method"], "OPTIONS")
        # ``wire_text`` is now split: ``raw_wire_text`` keeps CRLF for byte-
        # exact replay, and the human-readable LF-only form is rendered
        # outside the JSON. Tests that need the on-the-wire bytes use
        # ``raw_wire_text``.
        self.assertIn("raw_wire_text", payload)
        self.assertTrue(payload["raw_wire_text"].endswith("\r\n"))
        self.assertFalse(payload["raw_wire_text"].endswith("\r\n\r\n"))
        self.assertGreaterEqual(len(payload["records"]), 1)

    def test_request_command_generates_and_mutates_request_packet(self) -> None:
        result = self.runner.invoke(
            self.app,
            [
                "request",
                "OPTIONS",
                "--layer",
                "model",
                "--seed",
                "11",
                "--target",
                "max-forwards",
            ],
        )

        payload = self.parse_output(result)

        self.assertEqual(payload["final_layer"], "model")
        self.assertEqual(payload["seed"], 11)
        self.assertEqual(payload["original_packet"]["method"], "OPTIONS")
        self.assertEqual(payload["records"][0]["target"]["path"], "max_forwards")
        self.assertNotEqual(
            payload["mutated_packet"]["max_forwards"],
            payload["original_packet"]["max_forwards"],
        )

    def test_request_command_auto_selects_wire_layer_for_parser_breaker_default(self) -> None:
        result = self.runner.invoke(
            self.app,
            [
                "request",
                "OPTIONS",
                "--profile",
                "parser_breaker",
                "--seed",
                "19",
            ],
        )

        payload = self.parse_output(result)

        self.assertEqual(payload["profile"], "parser_breaker")
        self.assertEqual(payload["final_layer"], "wire")
        self.assertIn(
            payload["strategy"],
            {"final_crlf_loss", "duplicate_content_length_conflict", "edge_boundary"},
        )

    def test_request_command_auto_selects_byte_layer_for_explicit_byte_strategy(self) -> None:
        result = self.runner.invoke(
            self.app,
            [
                "request",
                "OPTIONS",
                "--profile",
                "parser_breaker",
                "--strategy",
                "tail_chop_1",
                "--seed",
                "23",
            ],
        )

        payload = self.parse_output(result)

        self.assertEqual(payload["profile"], "parser_breaker")
        self.assertEqual(payload["final_layer"], "byte")
        self.assertEqual(payload["strategy"], "tail_chop_1")
        # Both wire- and byte-layer mutations now publish the on-the-wire
        # bytes under the unified ``raw_wire_text`` key.
        self.assertIn("raw_wire_text", payload)

    def test_response_command_generates_and_mutates_response_packet(self) -> None:
        result = self.runner.invoke(
            self.app,
            [
                "response",
                "200",
                "INVITE",
                "--context",
                (
                    '{"call_id":"'
                    f"{REALISTIC_CALL_ID}"
                    '","local_tag":"'
                    f"{REALISTIC_LOCAL_TAG}"
                    '","local_cseq":7}'
                ),
                "--layer",
                "model",
                "--seed",
                "13",
                "--target",
                "reason-phrase",
            ],
        )

        payload = self.parse_output(result)

        self.assertEqual(payload["final_layer"], "model")
        self.assertEqual(payload["seed"], 13)
        self.assertEqual(payload["original_packet"]["status_code"], 200)
        self.assertEqual(payload["original_packet"]["cseq"]["method"], "INVITE")
        self.assertEqual(payload["records"][0]["target"]["path"], "reason_phrase")
        self.assertNotEqual(
            payload["mutated_packet"]["reason_phrase"],
            payload["original_packet"]["reason_phrase"],
        )

    def test_packet_command_accepts_realistic_wire_strategy(self) -> None:
        baseline_json = self.generate_request_baseline_json("OPTIONS")

        result = self.runner.invoke(
            self.app,
            [
                "packet",
                "--layer",
                "wire",
                "--seed",
                "17",
                "--strategy",
                "final_crlf_loss",
            ],
            input=baseline_json,
        )

        payload = self.parse_output(result)

        self.assertEqual(payload["strategy"], "final_crlf_loss")
        self.assertEqual(payload["final_layer"], "wire")
        self.assertTrue(payload["raw_wire_text"].endswith("\r\n"))
        self.assertFalse(payload["raw_wire_text"].endswith("\r\n\r\n"))

    def test_packet_command_warns_with_packet_flag_name_for_targeted_multi_mutation(self) -> None:
        baseline_json = self.generate_request_baseline_json("OPTIONS")

        result = self.runner.invoke(
            self.app,
            [
                "packet",
                "--profile",
                "legacy",
                "--layer",
                "wire",
                "--strategy",
                "default",
                "--target",
                "header[0]",
                "--max-operations",
                "3",
            ],
            input=baseline_json,
        )

        payload = self.parse_output(result)

        self.assertEqual(payload["final_layer"], "wire")
        self.assertIn("warning: --max-operations=3 ignored", result.output)
        self.assertNotIn("--mutations-per-case=3 ignored", result.output)

    def test_request_command_does_not_warn_when_invalid_target_combo_fails_early(self) -> None:
        result = self.runner.invoke(
            self.app,
            [
                "request",
                "OPTIONS",
                "--profile",
                "delivery_preserving",
                "--strategy",
                "null_byte_only",
                "--target",
                "header[0]",
                "--mutations-per-case",
                "3",
            ],
        )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn(
            "profile-scoped mutation does not support explicit targets",
            result.output,
        )
        self.assertNotIn("ignored because --target is set", result.output)

    def test_help_exposes_basic_mutation_options(self) -> None:
        expected_options = ("--profile", "--strategy", "--layer", "--seed", "--target")

        for command in ("packet", "request", "response"):
            with self.subTest(command=command):
                result = self.runner.invoke(self.app, [command, "--help"])

                self.assertEqual(result.exit_code, 0, msg=result.output)
                for option in expected_options:
                    self.assertIn(option, result.output)

    def test_packet_help_mentions_realistic_strategy_examples(self) -> None:
        result = self.runner.invoke(self.app, ["packet", "--help"])

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("final_crlf_loss", result.output)
        self.assertIn("tail_chop_1", result.output)
        self.assertIn("alias_port_desync", result.output)

    def test_commands_reject_invalid_profile_without_traceback(self) -> None:
        packet_input = self.generate_request_baseline_json("OPTIONS")
        cases = (
            ("packet", ["packet", "--profile", "unknown"], packet_input),
            ("request", ["request", "OPTIONS", "--profile", "unknown"], None),
            (
                "response",
                [
                    "response",
                    "200",
                    "INVITE",
                    "--context",
                    (
                        '{"call_id":"'
                        f"{REALISTIC_CALL_ID}"
                        '","local_tag":"'
                        f"{REALISTIC_LOCAL_TAG}"
                        '","local_cseq":7}'
                    ),
                    "--profile",
                    "unknown",
                ],
                None,
            ),
        )

        for name, args, command_input in cases:
            with self.subTest(command=name):
                result = self.runner.invoke(self.app, args, input=command_input)

                self.assertNotEqual(result.exit_code, 0)
                self.assertIn("unsupported mutation profile: unknown", result.output)
                self.assertNotIn("Traceback", result.output)

    def test_packet_command_rejects_invalid_input_json(self) -> None:
        result = self.runner.invoke(
            self.app,
            ["packet", "--layer", "model"],
            input='{"method":',
        )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Invalid value", result.output)


if __name__ == "__main__":
    unittest.main()
