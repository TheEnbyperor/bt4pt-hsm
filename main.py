import time
import asn1tools
import ecknr
import smartcard.System


PROTO = asn1tools.compile_files(["../bt4pt-asn1/asn1/bt4pt_barcode_header.asn", "../bt4pt-asn1/asn1/bt4pt_general_elements.asn"], codec="per")

AID = bytes.fromhex("E82B0601040183B764030100")

class RequestAPDU:
    instruction_class: int
    instruction: int
    p1: int
    p2: int
    data: bytes
    expected_response_length: int

    def __init__(
            self, instruction_class: int, instruction: int, p1: int, p2: int,
            data: bytes, expected_response_length: int
    ):
        self.instruction_class = instruction_class
        self.instruction = instruction
        self.p1 = p1
        self.p2 = p2
        self.data = data
        self.expected_response_length = expected_response_length

    def __str__(self):
        return (f"RequestAPDU(class={self.instruction_class:02x}, "
                f"instruction={self.instruction:02x}, "
                f"p1={self.p1:02x}, p2={self.p2:02x}, "
                f"data={self.data.hex().upper()}), "
                f"expected_response_length={self.expected_response_length})")

    def __repr__(self):
        return str(self)

    def encode(self):
        data_len = len(self.data)

        if self.expected_response_length == 0 and data_len == 0:
            raise ValueError("Expected response length cannot be 0 with no command data")

        out = bytearray([
            self.instruction_class,
            self.instruction,
            self.p1,
            self.p2,
        ])

        if data_len == 0:
            pass
        elif data_len < 256:
            out.append(data_len)
        elif data_len < 65536:
            out.append(0)
            out.extend(data_len.to_bytes(2, "big"))
        else:
            raise ValueError("Data length too long")
        out.extend(self.data)

        if self.expected_response_length == 0:
            pass
        else:
            if data_len >= 256:
                if self.expected_response_length == 65536:
                    out.append(0)
                    out.append(0)
                elif self.expected_response_length < 65536:
                    out.extend(self.expected_response_length.to_bytes(2, "big"))
                else:
                    raise ValueError("Invalid expected response length")
            else:
                if self.expected_response_length == 256:
                    out.append(0)
                elif self.expected_response_length == 65536:
                    out.append(0)
                    out.append(0)
                    out.append(0)
                elif self.expected_response_length < 256:
                    out.append(self.expected_response_length)
                elif self.expected_response_length < 65536:
                    out.append(0)
                    out.extend(self.expected_response_length.to_bytes(2, "big"))
                else:
                    raise ValueError("Invalid expected response length")
        return bytes(out)


class ResponseAPDU:
    sw1: int
    sw2: int
    data: bytes

    def __init__(self, sw1: int, sw2: int, data: bytes):
        self.sw1 = sw1
        self.sw2 = sw2
        self.data = data

    def __str__(self):
        return (f"ResponseAPDU(data={self.data.hex().upper()}, "
                f"sw1={self.sw1:02x}, sw2={self.sw2:02x})")

    def __repr__(self):
        return str(self)

    def is_success(self):
        return self.sw1 == 0x90 and self.sw2 == 0x00


def apdu(conn, req: RequestAPDU):
    data, sw1, sw2 = conn.transmit(list(req.encode()))
    return ResponseAPDU(sw1, sw2, bytes(data))


def select_application(aid: bytes):
    return RequestAPDU(
        instruction_class=0x00, instruction=0xA4, p1=0x04, p2=0x00,
        data=aid, expected_response_length=256
    )

def main():
    reader = smartcard.System.readers()[0]
    print("Reader:", reader)
    with reader.createConnection() as conn:
        conn.connect()
        resp = apdu(conn, select_application(AID))
        if not resp.is_success():
            raise RuntimeError("Failed to select applet")

        key_slot = 1

        resp = apdu(conn, RequestAPDU(
            instruction_class=0x80, instruction=0x30,
            p1=0x00, p2=0x00,
            data=b"", expected_response_length=256
        ))
        if not resp.is_success():
            raise RuntimeError(f"Failed to get HSM info: {resp.sw1:02x} {resp.sw2:02x}")
        print("HSM ID:", resp.data[0:8].hex())
        print("Signature counter:", int.from_bytes(resp.data[8:12], "big"))

        resp = apdu(conn, RequestAPDU(
            instruction_class=0x80, instruction=0x12,
            p1=key_slot, p2=0x00,
            data=b"", expected_response_length=256
        ))
        if not resp.is_success():
            raise RuntimeError(f"Failed to clear key slot: {resp.sw1:02x} {resp.sw2:02x}")

        resp = apdu(conn, RequestAPDU(
            instruction_class=0x80, instruction=0x10,
            p1=key_slot, p2=0x00,
            data=b"", expected_response_length=256
        ))
        if not resp.is_success():
            raise RuntimeError(f"Failed to generate key pair: {resp.sw1:02x} {resp.sw2:02x}")

        resp = apdu(conn, RequestAPDU(
            instruction_class=0x80, instruction=0x11,
            p1=key_slot, p2=0x00,
            data=b"", expected_response_length=256
        ))
        if not resp.is_success():
            raise RuntimeError(f"Failed to get public key: {resp.sw1:02x} {resp.sw2:02x}")
        print("EC public key:", resp.data.hex())

        public_key = ecknr.Secp256K1PublicKey.from_sec1(b"\x04" + resp.data)

        resp = apdu(conn, RequestAPDU(
            instruction_class=0x80, instruction=0x20,
            p1=0x00, p2=0x00,
            data=b"", expected_response_length=256
        ))
        if not resp.is_success():
            raise RuntimeError(f"Failed to clear ticket buffer: {resp.sw1:02x} {resp.sw2:02x}")

        resp = apdu(conn, RequestAPDU(
            instruction_class=0x80, instruction=0x21,
            p1=0x01, p2=0x06,
            data=b"5101X1TEST DATA 1", expected_response_length=256
        ))
        if not resp.is_success():
            raise RuntimeError(f"Failed to add data element 1: {resp.sw1:02x} {resp.sw2:02x}")

        resp = apdu(conn, RequestAPDU(
            instruction_class=0x80, instruction=0x21,
            p1=0x00, p2=0x06,
            data=b"5101X2TEST DATA 2", expected_response_length=256
        ))
        if not resp.is_success():
            raise RuntimeError(f"Failed to add data element 2: {resp.sw1:02x} {resp.sw2:02x}")

        resp = apdu(conn, RequestAPDU(
            instruction_class=0x80, instruction=0x22,
            p1=0x00, p2=0x00,
            data=(
                (2027).to_bytes(2, "big") +
                (300).to_bytes(2, "big") +
                (1312).to_bytes(2, "big")
            ),
            expected_response_length=256
        ))
        if not resp.is_success():
            raise RuntimeError(f"Failed to set expiry: {resp.sw1:02x} {resp.sw2:02x}")

        resp = apdu(conn, RequestAPDU(
            instruction_class=0x80, instruction=0x23,
            p1=0x02, p2=0x00,
            data=(
                (300).to_bytes(2, "big") +
                b"\x01" +
                (b"\x33" * 32)
            ),
            expected_response_length=256
        ))
        if not resp.is_success():
            raise RuntimeError(f"Failed to set device binding: {resp.sw1:02x} {resp.sw2:02x}")

        t = time.time()
        resp = apdu(conn, RequestAPDU(
            instruction_class=0x80, instruction=0x24,
            p1=key_slot, p2=0x00,
            data=b"", expected_response_length=256
        ))
        t = time.time() - t
        if not resp.is_success():
            raise RuntimeError(f"Failed to create ticket: {resp.sw1:02x} {resp.sw2:02x}")
        print(f"Ticket data:", resp.data.hex())
        print(f"Duration:", t)

        signature = ecknr.Signature(resp.data[0:32], resp.data[32:64], resp.data[64:])
        issuer_data = public_key.verify(signature)
        print(f"Issuer data:", issuer_data.hex())

        with open("barcode-data.per", "wb") as f:
            f.write(issuer_data)

        ticket_data = PROTO.decode("IssuerSignedData", issuer_data)
        print(ticket_data)

        for elm in ticket_data["data"]:
            if elm["format"] == "HSM1":
                print("HSM ID:", elm["value"][0:8].hex())
                print("Key slot:", elm["value"][8])
                print("Signature counter:", int.from_bytes(elm["value"][9:13], "big"))

if __name__ == "__main__":
    main()