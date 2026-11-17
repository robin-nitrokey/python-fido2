import hashlib
import secrets
from getpass import getpass
from typing import Any

from fido2.attestation.base import InvalidSignature
from fido2.attestation.packed import PackedAttestation
from fido2.client import ClientError as Fido2ClientError
from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction
from fido2.cose import ES256, EdDSA
from fido2.ctap import CtapError
from fido2.ctap2.base import Ctap2, Info
from fido2.ctap2.config import Config
from fido2.ctap2.credman import CredentialManagement
from fido2.ctap2.extensions import HMACGetSecretInput, HMACGetSecretOutput, HmacSecretExtension
from fido2.ctap2.pin import ClientPin, PinProtocol
from fido2.hid import CtapHidDevice, open_device
from fido2.webauthn import (
    Aaguid,
    AttestationObject,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)


class CliInteraction(UserInteraction):
    def __init__(self) -> None:
        pass

    def prompt_up(self) -> None:
        print("Touch your authenticator device now...")

    def request_pin(self, permissions: Any, rd_id: Any) -> str:
        return getpass("Enter PIN: ")

    def request_uv(self, permissions: Any, rd_id: Any) -> bool:
        return True


def _device() -> CtapHidDevice:
    devices = list(CtapHidDevice.list_devices())
    assert len(devices) == 1
    return devices[0]


def _fido2(
    device: CtapHidDevice, host: str
) -> Fido2Client:
    origin = f"https://{host}"
    client_data_collector = DefaultClientDataCollector(origin=origin)
    extensions = [HmacSecretExtension(allow_hmac_secret=True)]  # type: ignore[no-untyped-call]
    user_interaction = CliInteraction()
    return Fido2Client(
        device=device,
        client_data_collector=client_data_collector,
        extensions=extensions,
        user_interaction=user_interaction,
    )


def _make_credential(
    client: Fido2Client,
    host: str,
    user_id: str,
) -> AttestationObject:
    extensions = {"hmacCreateSecret": True}

    options = PublicKeyCredentialCreationOptions(
        rp=PublicKeyCredentialRpEntity(name="Example RP", id=host),
        user=PublicKeyCredentialUserEntity(name="A. User", id=user_id.encode()),
        challenge=secrets.token_bytes(32),
        pub_key_cred_params=[
            PublicKeyCredentialParameters(
                type=PublicKeyCredentialType.PUBLIC_KEY, alg=EdDSA.ALGORITHM
            ),
            PublicKeyCredentialParameters(
                type=PublicKeyCredentialType.PUBLIC_KEY, alg=ES256.ALGORITHM
            ),
        ],
        extensions=extensions,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.DISCOURAGED,
            user_verification=UserVerificationRequirement.DISCOURAGED,
        ),
    )

    registration_response = client.make_credential(options)

    attestation_response = registration_response.response
    att_obj = attestation_response.attestation_object
    assert att_obj.fmt == "packed"
    verifier = PackedAttestation()
    try:
        verifier.verify(att_obj.att_stmt, att_obj.auth_data, attestation_response.client_data.hash)
    except InvalidSignature:
        raise Exception("Invalid attestation signature in makeCredential")

    extension_outputs = registration_response.client_extension_results
    assert "hmacCreateSecret" in extension_outputs
    assert extension_outputs["hmacCreateSecret"] is True

    return att_obj


def _simple_secret(
    client: Fido2Client, credential_id: bytes, secret_input: str, host: str
) -> bytes:
    allow_list = [
        PublicKeyCredentialDescriptor(
            type=PublicKeyCredentialType.PUBLIC_KEY, id=credential_id
        )
    ]

    challenge = secrets.token_bytes(32)
    salt = hashlib.sha256(secret_input.encode()).digest()

    assertion = client.get_assertion(
        PublicKeyCredentialRequestOptions(
            challenge=challenge,
            rp_id=host,
            allow_credentials=allow_list,
            user_verification=UserVerificationRequirement.DISCOURAGED,
            extensions={"hmacGetSecret": HMACGetSecretInput(salt1=salt)},
        )
    ).get_response(0)

    assert "hmacGetSecret" in assertion.client_extension_results
    # from_dict would be more suitable but does not have type annotations
    output = HMACGetSecretOutput(**assertion.client_extension_results["hmacGetSecret"])

    return output.output1


if __name__ == "__main__":
    host = "example.com"

    device = _device()
    client = _fido2(device, host)
    attestation_object = _make_credential(client, host, "user")
    credential_id = attestation_object.auth_data.credential_data.credential_id
    _simple_secret(client, credential_id, "input", host=host)
    print("OK")
