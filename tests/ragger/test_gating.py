import pytest

from ragger.backend import BackendInterface
from ragger.navigator.navigation_scenario import NavigateWithScenario

from test_blind_sign import test_blind_sign as blind_sign

from client.client import EthAppClient
from client.gating import Gating
from client.status_word import StatusWord


def test_gating_descriptor(backend: BackendInterface) -> None:
    """Test the Gating descriptor APDU"""

    app_client = EthAppClient(backend)
    device = backend.device

    if device.name != "apex_p":
        pytest.skip("TODO: ONLY APEX_P supported for now")

    if device.is_nano:
        pytest.skip("Not yet supported on Nano")

    descriptor = Gating(
        bytes.fromhex("Dad77910DbDFdE764fC21FCD4E74D71bBACA6D8D"),
        1,
        "Intro message",
        "https://tinyurl.com/example",
    )

    response = app_client.provide_gating(descriptor)
    assert response.status == StatusWord.OK


def test_gating_blind_signing(scenario_navigator: NavigateWithScenario) -> None:
    """Test the Gating descriptor APDU with a blind signing transaction"""

    backend = scenario_navigator.backend
    app_client = EthAppClient(backend)
    device = backend.device

    if device.name != "apex_p":
        pytest.skip("TODO: ONLY APEX_P supported for now")

    if device.is_nano:
        pytest.skip("Not yet supported on Nano")

    descriptor = Gating(
        bytes.fromhex("Dad77910DbDFdE764fC21FCD4E74D71bBACA6D8D"),
        1,
        "To scan for threats and verify this transaction before signing, use Ledger Multisig.",
        "ledger.com/ledger-multisig",
    )

    response = app_client.provide_gating(descriptor)
    assert response.status == StatusWord.OK

    blind_sign(scenario_navigator.navigator,
               scenario_navigator,
               scenario_navigator.test_name,
               False,
               0.0,
               nb_warnings=2)
