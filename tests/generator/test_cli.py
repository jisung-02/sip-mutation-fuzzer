import json
from pathlib import Path
import unittest

from typer.testing import CliRunner

from volte_mutation_fuzzer.generator.cli import app


class SIPGeneratorCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = CliRunner()

    def test_request_command_prints_generated_packet_using_env_backed_settings(
        self,
    ) -> None:
        result = self.runner.invoke(
            app,
            ["request", "OPTIONS"],
            env={"VMF_GENERATOR_REQUEST_URI_HOST": "ims.example.net"},
        )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["method"], "OPTIONS")
        self.assertEqual(payload["request_uri"]["host"], "ims.example.net")
        self.assertEqual(payload["cseq"]["method"], "OPTIONS")
        self.assertEqual(payload["from"]["parameters"]["tag"] != "", True)

    def test_response_command_prints_generated_packet_from_context_json(self) -> None:
        result = self.runner.invoke(
            app,
            [
                "response",
                "200",
                "INVITE",
                "--context",
                '{"call_id":"call-1","local_tag":"ue-tag","local_cseq":7}',
            ],
        )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status_code"], 200)
        self.assertEqual(payload["reason_phrase"], "OK")
        self.assertEqual(payload["call_id"], "call-1")
        self.assertEqual(payload["cseq"]["sequence"], 7)
        self.assertEqual(payload["cseq"]["method"], "INVITE")

    def test_request_command_rejects_invalid_override_json(self) -> None:
        result = self.runner.invoke(
            app,
            [
                "request",
                "OPTIONS",
                "--override",
                '{"Max-Forwards":',
            ],
        )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Invalid value", result.output)
        self.assertIn("--override", result.output)

    def test_request_command_auto_loads_dotenv_file(self) -> None:
        with self.runner.isolated_filesystem():
            Path(".env").write_text(
                "VMF_GENERATOR_REQUEST_URI_HOST=ims.example.net\n",
                encoding="utf-8",
            )

            result = self.runner.invoke(app, ["request", "OPTIONS"])

        self.assertEqual(result.exit_code, 0, msg=result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["request_uri"]["host"], "ims.example.net")


if __name__ == "__main__":
    unittest.main()
