from typing import Optional
from .tlv import TlvSerializable, FieldTag
from .keychain import sign_data, Key


class Gating(TlvSerializable):
    address: bytes
    chain_id: int
    intro_message: str
    tiny_url: str
    selector: Optional[bytes]
    signature: Optional[bytes]

    def __init__(self,
                 address: bytes,
                 chain_id: int,
                 intro_message: str,
                 tiny_url: str,
                 selector: Optional[bytes] = None,
                 signature: Optional[bytes] = None) -> None:

        self.address = address
        self.chain_id = chain_id
        self.intro_message = intro_message
        self.tiny_url = tiny_url
        self.selector = selector
        self.signature = signature

    def serialize(self) -> bytes:
        assert self.address is not None, "Address is required"
        assert self.chain_id is not None, "Chain ID is required"
        assert self.intro_message is not None, "Intro message is required"
        assert self.tiny_url is not None, "Tiny URL is required"

        # Construct the TLV payload
        payload: bytes = self.serialize_field(FieldTag.STRUCT_TYPE, 0x0D)
        payload += self.serialize_field(FieldTag.STRUCT_VERSION, 1)
        payload += self.serialize_field(FieldTag.ADDRESS, self.address)
        payload += self.serialize_field(FieldTag.CHAIN_ID, self.chain_id.to_bytes(8, 'big'))
        payload += self.serialize_field(FieldTag.MESSAGE, self.intro_message.encode('utf-8'))
        payload += self.serialize_field(FieldTag.TINY_URL, self.tiny_url.encode('utf-8'))
        if self.selector:
            payload += self.serialize_field(FieldTag.SELECTOR, self.selector)
        # Append the data Signature
        sig = self.signature
        if sig is None:
            sig = sign_data(Key.GATING, payload)
        payload += self.serialize_field(FieldTag.DER_SIGNATURE, sig)
        return payload
