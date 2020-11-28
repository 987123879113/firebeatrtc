class BitArrayBuffer:
    def __init__(self, len):
        self.buffer = [0] * len


    def xor(self, buffer2):
        buffer1_len = len(self.buffer)
        buffer2_len = len(buffer2.buffer)
        output_buffer_len = min(buffer1_len, buffer2_len)
        new_buffer = [0] * output_buffer_len

        for i in range(output_buffer_len):
            new_buffer[i] = self.buffer[i] ^ buffer2.buffer[i]

        self.buffer = new_buffer


    def read(self, offset, bits):
        x = [1 << i for i in range(bits) if self.buffer[offset+i] != 0]
        return sum(x) if x else 0


    def write(self, offset, bits, input):
        for i in range(bits):
            self.buffer[offset + i] = 1 if (input & (1 << i)) != 0 else 0


class KonamiRand:
    def __init__(self):
        self.buffer_len = 55
        self.buffer = [0] * (self.buffer_len + 2)  # +2 for seed and read index


    def get_safe_val(self, val):
        return (val + (1000000000 if val < 0 else 0)) & 0xffffffff


    def scramble(self):
        def _inner_scramble(start, end, offset1, offset2):
            for i in range(start, end):
                val = self.get_safe_val(self.buffer[offset1 + i] - self.buffer[offset2 + i])
                self.buffer[offset1 + i] = val

        _inner_scramble(1, 25, 0, 0x1f)
        _inner_scramble(25, 56, 0, -0x18)


    def seed(self, input):
        self.buffer[-2] = input & 0xffffffff

        val = 1

        for i in range(1, 55):
            offset = (i * 21) % 55
            self.buffer[offset] = val
            val = self.get_safe_val(input - val)
            input = self.buffer[offset]

        self.scramble()
        self.scramble()
        self.scramble()

        self.buffer[-1] = self.buffer_len


    def next(self):
        self.buffer[-1] += 1

        if self.buffer[-1] > self.buffer_len:
            self.scramble()
            self.buffer[-1] = 1

        return self.buffer[self.buffer[-1]]


def base36encode(val, len, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"):
    output = ""

    for _ in range(len):
        val, i = divmod(val, 36)
        output += alphabet[i]

    return output


def base36decode(val, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"):
    output = 0

    for i, c in enumerate(val.upper()):
        output += alphabet.index(c) * (36 ** i)

    return output & 0xffffffff


def verify_date(date):
    # Konami's logic
    return date < 0xf2000 and ((date / 100) % 100) < 13 and (date % 100) < 32


def decode_firebeat_recovery_password(input):
    def buffer_to_str(buffer):
        parts = []

        for i in range(0, 70, 10):
            v = buffer.read(i, 10)
            parts.append((v // 100) % 10)
            parts.append((v // 10) % 10)
            parts.append(v % 10)

        v = buffer.read(70, 7)
        parts.append((v // 10) % 10)
        parts.append(v % 10)

        return "".join([str(c) for c in parts])

    input = input.replace("-", "")

    krand = KonamiRand()

    output_buffer = BitArrayBuffer(112)
    output_buffer.write(0, 31, base36decode(input[:6]))
    output_buffer.write(31, 31, base36decode(input[6:12]))
    output_buffer.write(62, 31, base36decode(input[12:18]))
    output_buffer.write(93, 10, base36decode(input[18:]))

    seed = output_buffer.read(93, 10)
    checksum_base = output_buffer.read(77, 16)

    krand.seed(seed * 3 + 0x70)

    checksum = (checksum_base ^ krand.next()) & 0xffff

    krand.seed(seed * 7 + checksum * 5 + 0x70)

    xor_buffer = BitArrayBuffer(108)
    xor_buffer.write(0, 32, krand.next())
    xor_buffer.write(32, 32, krand.next())
    xor_buffer.write(64, 13, krand.next())

    output_buffer.xor(xor_buffer)

    internal_sum = sum([
        output_buffer.read(0, 12),
        output_buffer.read(12, 12),
        output_buffer.read(24, 12),
        output_buffer.read(36, 12),
        output_buffer.read(48, 12),
        output_buffer.read(60, 12),
        output_buffer.read(72, 5),
    ]) & 0xffff


    output_str = buffer_to_str(output_buffer)
    serial_num = output_str[:9]
    keycode_num = output_str[9:17]
    date_num = output_str[17:]

    is_valid = checksum == internal_sum and len(serial_num) == 9 and len(keycode_num) == 8 and len(date_num) == 6 and verify_date(int(date_num))

    return {
        'password': input,
        'decoded': output_str,
        'serial': serial_num,
        'keycode': keycode_num,
        'date': date_num,
        'is_valid': is_valid,
    }


def encode_firebeat_recovery_password(serial, keycode, date, seed, verify_password=False):
    def generate_key(serial, keycode, date):
        assert(len(serial) == 9)
        assert(len(keycode) == 8)

        snum = "".join(["%c" % chr(ord(c) - (0x31 if ord(c) >= 0x61 else 0)) for c in serial.lower()])
        nnum = keycode
        dnum = "%06d" % (date if verify_date(date) else 0)

        return "".join([snum, nnum, dnum])


    def str_to_buffer(input):
        output_buffer = BitArrayBuffer(112)

        for i in range(len(input) // 3):
            output_buffer.write(i*10, 10, int(input[i*3:(i*3)+3]))

        i = len(input) // 3
        output_buffer.write(70, 7, int(input[i*3:(i*3)+3]))

        return output_buffer

    date = int(date)
    seed = int(seed)

    k = generate_key(serial, keycode, date)
    output_buffer = str_to_buffer(k)

    internal_sum = sum([
        output_buffer.read(0, 12),
        output_buffer.read(12, 12),
        output_buffer.read(24, 12),
        output_buffer.read(36, 12),
        output_buffer.read(48, 12),
        output_buffer.read(60, 12),
        output_buffer.read(72, 5),
    ]) & 0xffff

    krand = KonamiRand()
    krand.seed(seed * 3 + 0x70)

    checksum = (internal_sum ^ krand.next()) & 0xffff
    output_buffer.write(77, 16, checksum)
    output_buffer.write(93, 10, seed)

    krand.seed(seed * 7 + internal_sum * 5 + 0x70)

    xor_buffer = BitArrayBuffer(108)
    xor_buffer.write(0, 32, krand.next())
    xor_buffer.write(32, 32, krand.next())
    xor_buffer.write(64, 13, krand.next())

    output_buffer.xor(xor_buffer)

    parts = [
        base36encode(output_buffer.read(0, 31), 6),
        base36encode(output_buffer.read(31, 31), 6),
        base36encode(output_buffer.read(62, 31), 6),
        base36encode(output_buffer.read(93, 10), 2),
    ]

    parts_str = "".join(parts)
    password = "-".join([parts_str[i:i+5] for i in range(0, len(parts_str), 5)])

    if verify_password:
        decoded_password = decode_firebeat_recovery_password(password)

        if not decoded_password['is_valid']:
            return "FAILED"

    return password
