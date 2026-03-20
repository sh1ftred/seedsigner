import json

from seedsigner.models.nostr_bunker import NostrSigner


def test_nip44_roundtrip_between_two_keys():
    a = NostrSigner.generate()
    b = NostrSigner.generate()

    plaintext = json.dumps({"id": "1", "method": "ping", "params": []}, separators=(",", ":"))
    payload = NostrSigner.encrypt_nip44(a.private_key_hex, b.public_key_hex, plaintext)
    decrypted = NostrSigner.decrypt_nip44(b.private_key_hex, a.public_key_hex, payload)

    assert decrypted == plaintext


def test_nip44_known_vector_conversation_key():
    sec1 = "0000000000000000000000000000000000000000000000000000000000000001"
    sec2 = "0000000000000000000000000000000000000000000000000000000000000002"
    pub2 = NostrSigner(sec2).public_key_hex
    conversation_key = NostrSigner.get_nip44_conversation_key(sec1, pub2)

    assert conversation_key.hex() == "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d"
