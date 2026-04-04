from volte_mutation_fuzzer.dialog.contracts import DialogScenarioType
from volte_mutation_fuzzer.dialog.scenarios import scenario_for_method


class TestScenarioForMethod:
    def test_bye_returns_invite_dialog(self) -> None:
        scenario = scenario_for_method("BYE")
        assert scenario is not None
        assert scenario.scenario_type == DialogScenarioType.invite_dialog
        assert scenario.fuzz_method == "BYE"

    def test_update_returns_invite_dialog(self) -> None:
        scenario = scenario_for_method("UPDATE")
        assert scenario is not None
        assert scenario.scenario_type == DialogScenarioType.invite_dialog

    def test_refer_returns_invite_dialog(self) -> None:
        scenario = scenario_for_method("REFER")
        assert scenario is not None
        assert scenario.scenario_type == DialogScenarioType.invite_dialog

    def test_info_returns_invite_dialog(self) -> None:
        scenario = scenario_for_method("INFO")
        assert scenario is not None
        assert scenario.scenario_type == DialogScenarioType.invite_dialog

    def test_cancel_returns_invite_cancel(self) -> None:
        scenario = scenario_for_method("CANCEL")
        assert scenario is not None
        assert scenario.scenario_type == DialogScenarioType.invite_cancel
        assert scenario.fuzz_method == "CANCEL"

    def test_ack_returns_invite_ack(self) -> None:
        scenario = scenario_for_method("ACK")
        assert scenario is not None
        assert scenario.scenario_type == DialogScenarioType.invite_ack
        assert scenario.fuzz_method == "ACK"

    def test_options_returns_none(self) -> None:
        assert scenario_for_method("OPTIONS") is None

    def test_invite_returns_none(self) -> None:
        assert scenario_for_method("INVITE") is None

    def test_register_returns_none(self) -> None:
        assert scenario_for_method("REGISTER") is None

    def test_message_returns_none(self) -> None:
        assert scenario_for_method("MESSAGE") is None


class TestInviteDialogScenarioStructure:
    def test_bye_setup_has_invite_and_ack(self) -> None:
        scenario = scenario_for_method("BYE")
        assert scenario is not None
        methods = [s.method for s in scenario.setup_steps]
        assert methods == ["INVITE", "ACK"]

    def test_bye_invite_step_expects_2xx(self) -> None:
        scenario = scenario_for_method("BYE")
        assert scenario is not None
        invite_step = scenario.setup_steps[0]
        assert invite_step.expect_status_min == 200
        assert invite_step.expect_status_max == 299

    def test_bye_fuzz_step_is_fuzz_target(self) -> None:
        scenario = scenario_for_method("BYE")
        assert scenario is not None
        assert scenario.fuzz_step.is_fuzz_target is True
        assert scenario.fuzz_step.method == "BYE"

    def test_bye_has_no_teardown_bye(self) -> None:
        # BYE IS the target, so no additional BYE teardown
        scenario = scenario_for_method("BYE")
        assert scenario is not None
        assert scenario.teardown_steps == ()

    def test_update_has_bye_teardown(self) -> None:
        scenario = scenario_for_method("UPDATE")
        assert scenario is not None
        assert len(scenario.teardown_steps) == 1
        assert scenario.teardown_steps[0].method == "BYE"

    def test_info_has_bye_teardown(self) -> None:
        scenario = scenario_for_method("INFO")
        assert scenario is not None
        assert len(scenario.teardown_steps) == 1
        assert scenario.teardown_steps[0].method == "BYE"


class TestInviteCancelScenarioStructure:
    def test_cancel_setup_has_invite_only(self) -> None:
        scenario = scenario_for_method("CANCEL")
        assert scenario is not None
        assert len(scenario.setup_steps) == 1
        assert scenario.setup_steps[0].method == "INVITE"

    def test_cancel_invite_step_expects_1xx(self) -> None:
        scenario = scenario_for_method("CANCEL")
        assert scenario is not None
        invite_step = scenario.setup_steps[0]
        assert invite_step.expect_status_min == 100
        assert invite_step.expect_status_max == 199

    def test_cancel_has_no_teardown(self) -> None:
        scenario = scenario_for_method("CANCEL")
        assert scenario is not None
        assert scenario.teardown_steps == ()


class TestInviteAckScenarioStructure:
    def test_ack_setup_has_invite_only(self) -> None:
        scenario = scenario_for_method("ACK")
        assert scenario is not None
        assert len(scenario.setup_steps) == 1
        assert scenario.setup_steps[0].method == "INVITE"

    def test_ack_has_bye_teardown(self) -> None:
        scenario = scenario_for_method("ACK")
        assert scenario is not None
        assert len(scenario.teardown_steps) == 1
        assert scenario.teardown_steps[0].method == "BYE"


class TestInvitePrackScenarioStructure:
    def test_prack_returns_invite_prack(self) -> None:
        scenario = scenario_for_method("PRACK")
        assert scenario is not None
        assert scenario.scenario_type == DialogScenarioType.invite_prack
        assert scenario.fuzz_method == "PRACK"

    def test_prack_setup_has_invite_only(self) -> None:
        scenario = scenario_for_method("PRACK")
        assert scenario is not None
        assert len(scenario.setup_steps) == 1
        assert scenario.setup_steps[0].method == "INVITE"

    def test_prack_invite_step_expects_1xx(self) -> None:
        scenario = scenario_for_method("PRACK")
        assert scenario is not None
        invite_step = scenario.setup_steps[0]
        assert invite_step.expect_status_min == 100
        assert invite_step.expect_status_max == 199

    def test_prack_fuzz_step_is_fuzz_target(self) -> None:
        scenario = scenario_for_method("PRACK")
        assert scenario is not None
        assert scenario.fuzz_step.is_fuzz_target is True
        assert scenario.fuzz_step.method == "PRACK"

    def test_prack_has_no_teardown(self) -> None:
        scenario = scenario_for_method("PRACK")
        assert scenario is not None
        assert scenario.teardown_steps == ()
