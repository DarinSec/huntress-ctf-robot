"""Synthetic DEX files for dexvm.py: Day 23's computed Release.code(), built instruction by instruction.

The builder writes a minimal classes.dex (one class, its methods and code items) so the
emulator is checked against Python's own 64-bit arithmetic, never against a real app.
"""

from io import BytesIO
import json
import struct
import unittest
import zipfile
from types import SimpleNamespace

from huntress_ctf import dexvm
from huntress_ctf.solvers.mobile_puzzle import answer_code

M64 = (1 << 64) - 1
K1, K2 = 0x2F0E43A1C59B7D13, 0x9E3779B97F4A7C15


def uleb(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def build_dex(strings, types, protos, methods, class_type, direct_methods, fields=()):
    """types: string indexes; protos: (return type, [param types]); methods and fields: (class, proto or type, name)."""
    header = 0x70
    sizes = [len(strings), len(types), len(protos), len(fields), len(methods), 1]
    offsets, at = [], header
    for count, width in zip(sizes, (4, 4, 12, 8, 8, 32)):
        offsets.append(at if count else 0)
        at += count * width
    data = bytearray(at)
    blobs = []

    def place(blob, align=1):
        nonlocal data
        while len(data) % align:
            data.append(0)
        start = len(data)
        data += blob
        return start

    for index, text in enumerate(strings):
        raw = text.encode()
        struct.pack_into("<I", data, offsets[0] + 4 * index, place(uleb(len(text)) + raw + b"\0"))
    for index, string in enumerate(types):
        struct.pack_into("<I", data, offsets[1] + 4 * index, string)
    for index, (ret, params) in enumerate(protos):
        params_at = place(struct.pack("<I", len(params)) + b"".join(struct.pack("<H", p) for p in params), 4) if params else 0
        struct.pack_into("<III", data, offsets[2] + 12 * index, 0, ret, params_at)
    for index, (cls, kind, name) in enumerate(fields):
        struct.pack_into("<HHI", data, offsets[3] + 8 * index, cls, kind, name)
    for index, (cls, proto, name) in enumerate(methods):
        struct.pack_into("<HHI", data, offsets[4] + 8 * index, cls, proto, name)
    codes = []
    for method_index, flags, registers, ins, insns in direct_methods:
        body = struct.pack("<HHHHII", registers, ins, 4, 0, 0, len(insns)) + struct.pack(f"<{len(insns)}H", *insns)
        codes.append((method_index, flags, place(body, 4)))
    class_data = uleb(0) + uleb(0) + uleb(len(codes)) + uleb(0)
    previous = 0
    for method_index, flags, code_at in codes:
        class_data += uleb(method_index - previous) + uleb(flags) + uleb(code_at)
        previous = method_index
    class_at = place(class_data)
    struct.pack_into("<8I", data, offsets[5], class_type, 1, 0xFFFFFFFF, 0, 0xFFFFFFFF, 0, class_at, 0)
    data[:8] = b"dex\n035\0"
    struct.pack_into("<12I", data, 0x38, *[value for pair in zip(sizes, offsets) for value in pair])
    return bytes(data)


def release_dex():
    strings = ["ANS-", "J", "LRelease;", "Landroid/content/Context;", "Ljava/lang/Long;",
               "Ljava/lang/String;", "Ljava/lang/StringBuilder;", "V", "<init>", "append", "code",
               "mix", "toHexString", "toString", "toUpperCase", "rotateLeft", "I"]
    s = {text: index for index, text in enumerate(strings)}
    types = [s[name] for name in ("J", "LRelease;", "Landroid/content/Context;", "Ljava/lang/Long;",
                                  "Ljava/lang/String;", "Ljava/lang/StringBuilder;", "V", "I")]
    t = {strings[string]: index for index, string in enumerate(types)}
    protos = [(t["J"], [t["J"]]), (t["Ljava/lang/String;"], [t["Landroid/content/Context;"]]),
              (t["V"], []), (t["Ljava/lang/StringBuilder;"], [t["Ljava/lang/String;"]]),
              (t["Ljava/lang/String;"], [t["J"]]), (t["Ljava/lang/String;"], []), (t["J"], [t["J"], t["I"]])]
    methods = [(t["LRelease;"], 1, s["code"]), (t["LRelease;"], 0, s["mix"]),
               (t["Ljava/lang/StringBuilder;"], 2, s["<init>"]), (t["Ljava/lang/StringBuilder;"], 3, s["append"]),
               (t["Ljava/lang/Long;"], 4, s["toHexString"]), (t["Ljava/lang/StringBuilder;"], 5, s["toString"]),
               (t["Ljava/lang/String;"], 5, s["toUpperCase"]), (t["Ljava/lang/Long;"], 6, s["rotateLeft"])]

    def wide(register, value):
        value &= M64
        return [0x18 | register << 8] + [(value >> shift) & 0xFFFF for shift in (0, 16, 32, 48)]

    # static long mix(long j) { j ^= K1; j *= K2; j = Long.rotateLeft(j, 23); return j ^ (j >>> 29) + 7; }  (j in v4/v5)
    mix = (wide(0, K1) + [0xC2 | 0x04 << 8]                              # xor-long/2addr v4, v0
           + wide(0, K2) + [0xBD | 0x04 << 8]                            # mul-long/2addr v4, v0
           + [0x13 | 2 << 8, 23]                                         # const/16 v2, 23
           + [0x71 | 3 << 12, 7, 0x0254]                                 # invoke-static {v4, v5, v2}, rotateLeft
           + [0x0B | 4 << 8]                                             # move-result-wide v4
           + [0x13 | 2 << 8, 29, 0x04 | (0 | 4 << 4) << 8]               # const/16 v2, 29; move-wide v0, v4
           + [0xA5 | 0 << 8, 0x0200 | 0]                                 # ushr-long v0, v0, v2
           + [0x16 | 2 << 8, 7, 0xBB | 0x20 << 8]                        # const-wide/16 v2, 7; add-long/2addr v0, v2
           + [0xC2 | 0x04 << 8, 0x10 | 4 << 8])                          # xor-long/2addr v4, v0; return-wide v4
    # static String code(Context c) { long v = mix(0x0123456789ABCDEF); return "ANS-" + Long.toHexString(v).toUpperCase(); }
    code = (wide(0, 0x0123456789ABCDEF)
            + [0x71 | 2 << 12, 1, 0x0010, 0x0B | 0 << 8]                 # invoke-static {v0, v1}, mix; move-result-wide v0
            + [0x22 | 2 << 8, 5, 0x70 | 1 << 12, 2, 0x0002]              # new-instance v2, StringBuilder; <init>
            + [0x1A | 3 << 8, 0, 0x6E | 2 << 12, 3, 0x0032]              # const-string v3, "ANS-"; append
            + [0x71 | 2 << 12, 4, 0x0010, 0x0C | 3 << 8]                 # toHexString(v0, v1); move-result-object v3
            + [0x6E | 1 << 12, 6, 0x0003, 0x0C | 3 << 8]                 # toUpperCase; move-result-object v3
            + [0x6E | 2 << 12, 3, 0x0032]                                # append(v2, v3)
            + [0x6E | 1 << 12, 5, 0x0002, 0x0C | 3 << 8, 0x11 | 3 << 8])  # toString; return-object v3
    return build_dex(strings, types, protos, methods, t["LRelease;"],
                     [(0, 0x9, 5, 1, code), (1, 0x8, 6, 2, mix)])


def expected():
    j = (0x0123456789ABCDEF ^ K1) * K2 & M64
    j = ((j << 23) | (j >> 41)) & M64
    j ^= ((j >> 29) + 7) & M64
    return f"ANS-{j:016X}"


def apk(dex, puzzle):
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("classes.dex", dex)
        archive.writestr("assets/huntress_puzzle.json", json.dumps(puzzle))
    return buffer.getvalue()


def der(tag, body):
    size = len(body)
    length = bytes([size]) if size < 128 else bytes([0x80 | (size.bit_length() + 7) // 8]) + size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([tag]) + length + body


def manifest(package, version_code, version_name):
    """Android binary XML: <manifest package=.. versionCode=.. versionName=..>; an int name is a resource reference."""
    strings = ["manifest", "package", package, "versionCode", "versionName", version_name if isinstance(version_name, str) else ""]
    encoded = [struct.pack("<H", len(text)) + text.encode("utf-16-le") + b"\0\0" for text in strings]
    offsets = [sum(len(item) for item in encoded[:index]) for index in range(len(strings))]
    body = b"".join(encoded)
    body += b"\0" * (-len(body) % 4)
    pool = struct.pack("<HHIIIIII", 1, 28, 28 + 4 * len(strings) + len(body), len(strings), 0, 0,
                       28 + 4 * len(strings), 0) + struct.pack(f"<{len(strings)}I", *offsets) + body
    attributes = [(1, 2, 0x03, 2), (3, 0xFFFFFFFF, 0x10, version_code),
                  (4, 5, 0x03, 5) if isinstance(version_name, str) else (4, 0xFFFFFFFF, 0x01, version_name)]
    attrs = b"".join(struct.pack("<IIIHxBI", 0xFFFFFFFF, key, raw, 8, kind, value) for key, raw, kind, value in attributes)
    ext = struct.pack("<IIHHHHHH", 0xFFFFFFFF, 0, 20, 20, len(attributes), 0, 0, 0)
    element = struct.pack("<HHIII", 0x0102, 16, 16 + len(ext) + len(attrs), 1, 0xFFFFFFFF) + ext + attrs
    return struct.pack("<HHI", 3, 8, 8 + len(pool) + len(element)) + pool + element


def signed_apk(certificate, package="com.example.signed", version_name="1.4.2"):
    """An APK whose META-INF/CERT.RSA is a PKCS#7 SignedData carrying `certificate`."""
    signed_data = der(0x30, der(0x02, b"\x01") + der(0x31, b"") + der(0x30, der(0x06, bytes.fromhex("2a864886f70d010701")))
                      + der(0xA0, certificate) + der(0x31, b""))
    pkcs7 = der(0x30, der(0x06, bytes.fromhex("2a864886f70d010702")) + der(0xA0, signed_data))
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", manifest(package, 42, version_name))
        archive.writestr("classes.dex", release_dex())
        archive.writestr("META-INF/CERT.RSA", pkcs7)
    return buffer.getvalue()


class LaterDayPlatformTests(unittest.TestCase):
    """Platform APIs no day 1-25 app used, computed from the APK bytes (or refused)."""

    def setUp(self):
        import base64
        from tests.test_formats_dfir import CERT_B64

        self.certificate = base64.b64decode(CERT_B64)
        self.apk = signed_apk(self.certificate)
        self.vm = dexvm.Machine([], package="com.example.signed", apk=self.apk)

    def call(self, cls, name, sig, *args):
        return dexvm._platform(cls, name, sig, list(args), self.vm)

    def new(self, kind, sig, *args):
        made = dexvm._PLATFORM_NEW[kind]()
        self.call(kind, "<init>", sig, made, *args)
        return made

    def test_charsets(self):
        utf8, latin = dexvm._PLATFORM_STATICS[("Ljava/nio/charset/StandardCharsets;", "UTF_8")], dexvm.Charset("ISO-8859-1")
        get = lambda text, charset: self.call("Ljava/lang/String;", "getBytes", "(Ljava/nio/charset/Charset;)[B", text, charset)
        self.assertEqual((get("é", utf8), get("é", latin), get("é", "UTF-16")), ([-61, -87], [-23], [-2, -1, 0, -23]))
        decode = lambda sig, *args: self.call("Ljava/lang/String;", "<init>", sig, None, *args)
        self.assertEqual(decode("([BIILjava/nio/charset/Charset;)V", [0x41, -23, 0x42], 1, 2, latin), "éB")
        self.assertEqual(decode("([BLjava/lang/String;)V", [0, 0x41], "UTF-16"), "A")
        self.assertEqual(decode("([BII)V", [0x41, 0x42, 0x43], 1, 1), "B")  # Offset and length are honoured.
        with self.assertRaises(dexvm.Unsupported):
            self.call("Ljava/nio/charset/Charset;", "forName", "", "Shift_JIS")

    def test_cipher_modes_like_javax_crypto(self):
        from huntress_ctf import ciphers

        key, iv, plain = bytes(range(16)), bytes(range(16, 32)), b"ANS-0123456789ABCDEF and some more"
        spec = self.new("Ljavax/crypto/spec/SecretKeySpec;", "([BLjava/lang/String;)V", dexvm._signed_bytes(key), "AES")
        ivspec = self.new("Ljavax/crypto/spec/IvParameterSpec;", "([B)V", dexvm._signed_bytes(iv))
        sealed = ciphers.cbc_encrypt(key, iv, ciphers.pad(plain))

        def cipher(transformation, mode, params, *chunks):
            state = self.call("Ljavax/crypto/Cipher;", "getInstance", "", transformation)
            self.call("Ljavax/crypto/Cipher;", "init", "", state, mode, spec, *([params] if params else []))
            out = []
            for chunk in chunks[:-1]:
                out += self.call("Ljavax/crypto/Cipher;", "update", "([B)[B", state, dexvm._signed_bytes(chunk))
            return dexvm._bytes(out + self.call("Ljavax/crypto/Cipher;", "doFinal", "([B)[B", state, dexvm._signed_bytes(chunks[-1])))

        self.assertEqual(cipher("AES/CBC/PKCS5Padding", 2, ivspec, sealed), plain)
        self.assertEqual(cipher("AES/CBC/PKCS5Padding", 2, ivspec, sealed[:20], sealed[20:32], sealed[32:]), plain)
        self.assertEqual(cipher("AES/CBC/PKCS5Padding", 1, ivspec, plain[:5], plain[5:]), sealed)
        self.assertEqual(cipher("AES", 2, None, cipher("AES/ECB/PKCS5Padding", 1, None, plain)), plain)
        self.assertEqual(cipher("AES/CTR/NoPadding", 2, ivspec, plain[:7], plain[7:]), ciphers.ctr(key, iv, plain))
        nonce = self.new("Ljavax/crypto/spec/GCMParameterSpec;", "(I[B)V", 128, dexvm._signed_bytes(iv[:12]))
        gcm = ciphers.ctr(key, iv[:12] + b"\0\0\0\2", plain, width=32) + bytes(16)  # The tag is not checked.
        self.assertEqual(cipher("AES/GCM/NoPadding", 2, nonce, gcm), plain)
        rc4 = cipher("RC4", 1, None, bytes(16))
        self.assertEqual(rc4, ciphers.rc4(key, bytes(16)))
        for bad in (lambda: cipher("AES/CBC/PKCS5Padding", 2, ivspec, sealed[:-1] + bytes([sealed[-1] ^ 1])),  # BadPadding
                    lambda: cipher("AES/CBC/PKCS5Padding", 1, None, plain),  # Java would pick a random IV.
                    lambda: cipher("DESede/CBC/PKCS5Padding", 2, ivspec, sealed),
                    lambda: self.call("Ljavax/crypto/Cipher;", "doFinal", "([BI)I",
                                      self.call("Ljavax/crypto/Cipher;", "getInstance", "", "AES"), [0] * 16, 0)):
            with self.assertRaises(dexvm.Unsupported):
                bad()

    def test_mac_pbkdf2_and_biginteger(self):
        key = self.new("Ljavax/crypto/spec/SecretKeySpec;", "([BLjava/lang/String;)V", dexvm._signed_bytes(b"Jefe"), "HmacSHA256")
        mac = self.call("Ljavax/crypto/Mac;", "getInstance", "", "HmacSHA256")
        self.call("Ljavax/crypto/Mac;", "init", "", mac, key)
        self.call("Ljavax/crypto/Mac;", "update", "([B)V", mac, dexvm._signed_bytes(b"what do ya want "))
        digest = self.call("Ljavax/crypto/Mac;", "doFinal", "([B)[B", mac, dexvm._signed_bytes(b"for nothing?"))
        self.assertEqual(dexvm._bytes(digest).hex(), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")  # RFC 4231 #2
        again = self.call("Ljavax/crypto/Mac;", "doFinal", "([B)[B", mac, dexvm._signed_bytes(b"what do ya want for nothing?"))
        self.assertEqual(again, digest)  # doFinal resets to the initialized key.
        spec = self.new("Ljavax/crypto/spec/PBEKeySpec;", "([C[BII)V", [ord(c) for c in "password"],
                        dexvm._signed_bytes(b"salt"), 2, 160)
        factory = self.call("Ljavax/crypto/SecretKeyFactory;", "getInstance", "", "PBKDF2WithHmacSHA1")
        derived = self.call("Ljavax/crypto/SecretKeyFactory;", "generateSecret", "", factory, spec)
        self.assertEqual(dexvm._bytes(self.call("Ljavax/crypto/SecretKey;", "getEncoded", "()[B", derived)).hex(),
                         "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957")  # RFC 6070, c = 2
        number = self.new("Ljava/math/BigInteger;", "(I[B)V", 1, [0, 0x0F, -1])
        self.assertEqual(self.call("Ljava/math/BigInteger;", "toString", "(I)Ljava/lang/String;", number, 16), "fff")
        negative = self.new("Ljava/math/BigInteger;", "([B)V", [-1, 0])
        self.assertEqual(self.call("Ljava/math/BigInteger;", "toString", "()Ljava/lang/String;", negative), "-256")
        self.assertEqual(self.call("Ljava/math/BigInteger;", "toByteArray", "()[B", negative), [-1, 0])
        seven = self.call("Ljava/math/BigInteger;", "valueOf", "(J)Ljava/math/BigInteger;", -7)
        three = self.call("Ljava/math/BigInteger;", "valueOf", "(J)Ljava/math/BigInteger;", 3)
        results = [self.call("Ljava/math/BigInteger;", op, "", seven, three).value for op in ("divide", "remainder", "mod", "xor")]
        self.assertEqual(results, [-2, -1, 2, -7 ^ 3])  # Java truncates; mod is never negative.

    def test_own_package_signature_and_apk(self):
        pm = self.call("Landroid/content/Context;", "getPackageManager", "", self.vm.context)
        info = self.call("Landroid/content/pm/PackageManager;", "getPackageInfo", "", pm, "com.example.signed", 0x40)
        self.assertEqual((info.fields["versionName"], info.fields["versionCode"]), ("1.4.2", 42))
        self.assertEqual(self.call("Landroid/content/pm/PackageInfo;", "getLongVersionCode", "()J", info), 42)
        signature = info.fields["signatures"][0]
        self.assertEqual(dexvm._bytes(self.call("Landroid/content/pm/Signature;", "toByteArray", "()[B", signature)),
                         self.certificate)
        self.assertEqual(self.call("Landroid/content/pm/Signature;", "toCharsString", "", signature), self.certificate.hex())
        self.assertEqual(self.call("Landroid/content/pm/Signature;", "hashCode", "()I", signature),
                         self.call("Ljava/util/Arrays;", "hashCode", "([B)I", dexvm._signed_bytes(self.certificate)))
        rotated = self.call("Landroid/content/pm/PackageManager;", "getPackageInfo", "", pm, "com.example.signed", 0x08000000)
        signers = self.call("Landroid/content/pm/SigningInfo;", "getApkContentsSigners", "", rotated.fields["signingInfo"])
        self.assertEqual(signers[0].data, self.certificate)
        self.assertIsNone(info.fields["signingInfo"])  # Not asked for: null, as on a device.
        stream = self.new("Ljava/io/ByteArrayInputStream;", "([B)V", dexvm._signed_bytes(self.certificate + b"tail"))
        factory = self.call("Ljava/security/cert/CertificateFactory;", "getInstance", "", "X.509")
        cert = self.call("Ljava/security/cert/CertificateFactory;", "generateCertificate", "", factory, stream)
        self.assertEqual(self.call("Ljava/security/cert/Certificate;", "getEncoded", "()[B", cert),
                         dexvm._signed_bytes(self.certificate))
        path = self.call("Landroid/content/Context;", "getPackageCodePath", "", self.vm.context)
        archive = self.new("Ljava/util/zip/ZipFile;", "(Ljava/lang/String;)V", path)
        entry = self.call("Ljava/util/zip/ZipFile;", "getEntry", "", archive, "classes.dex")
        with zipfile.ZipFile(BytesIO(self.apk)) as real:
            info_dex = real.getinfo("classes.dex")
        self.assertEqual((self.call("Ljava/util/zip/ZipEntry;", "getCrc", "()J", entry),
                          self.call("Ljava/util/zip/ZipEntry;", "getSize", "()J", entry)), (info_dex.CRC, info_dex.file_size))
        self.assertIsNone(self.call("Ljava/util/zip/ZipFile;", "getEntry", "", archive, "missing.bin"))
        source = self.call("Landroid/content/Context;", "getApplicationInfo", "", self.vm.context).fields["sourceDir"]
        handle = self.new("Ljava/io/File;", "(Ljava/lang/String;)V", source)
        self.assertEqual(self.call("Ljava/io/File;", "length", "()J", handle), len(self.apk))
        for bad in (lambda: self.call("Landroid/content/pm/PackageManager;", "getPackageInfo", "", pm, "com.android.vending", 0),
                    lambda: self.new("Ljava/util/zip/ZipFile;", "(Ljava/lang/String;)V", "/data/app/other.apk"),
                    lambda: self.call("Ljava/lang/StringBuilder;", "append", "(Ljava/lang/Object;)", dexvm.Builder(), path),
                    lambda: dexvm._signers(apk(release_dex(), {}))):  # No v1 certificate.
            with self.assertRaises(dexvm.Unsupported):
                bad()
        # versionName="@string/..." is resolved by the device from resources: using it stops the run.
        self.vm = dexvm.Machine([], package="com.example.signed", apk=signed_apk(self.certificate, version_name=0x7F0D0001))
        pm = self.call("Landroid/content/Context;", "getPackageManager", "", self.vm.context)
        name = self.call("Landroid/content/pm/PackageManager;", "getPackageInfo", "", pm, "com.example.signed", 0).fields["versionName"]
        with self.assertRaises(dexvm.Unsupported):
            self.call("Ljava/lang/StringBuilder;", "append", "(Ljava/lang/String;)", dexvm.Builder(), name)

    def test_bytecode_reaches_platform_new_and_static_fields(self):
        # static String code(Context c) { return new BigInteger(1, "abc".getBytes(StandardCharsets.UTF_8)).toString(16); }
        strings = ["LCode;", "Landroid/content/Context;", "Ljava/lang/String;", "Ljava/nio/charset/Charset;",
                   "Ljava/nio/charset/StandardCharsets;", "Ljava/math/BigInteger;", "[B", "I", "V", "UTF_8",
                   "getBytes", "<init>", "toString", "code", "abc"]
        s = {text: index for index, text in enumerate(strings)}
        types = [s[name] for name in strings[:9]]
        t = {strings[string]: index for index, string in enumerate(types)}
        protos = [(t["Ljava/lang/String;"], [t["Landroid/content/Context;"]]), (t["[B"], [t["Ljava/nio/charset/Charset;"]]),
                  (t["V"], [t["I"], t["[B"]]), (t["Ljava/lang/String;"], [t["I"]])]
        methods = [(t["LCode;"], 0, s["code"]), (t["Ljava/lang/String;"], 1, s["getBytes"]),
                   (t["Ljava/math/BigInteger;"], 2, s["<init>"]), (t["Ljava/math/BigInteger;"], 3, s["toString"])]
        fields = [(t["Ljava/nio/charset/StandardCharsets;"], t["Ljava/nio/charset/Charset;"], s["UTF_8"])]
        code = ([0x62 | 0 << 8, 0, 0x1A | 1 << 8, s["abc"]]                 # sget-object v0, UTF_8; const-string v1, "abc"
                + [0x6E | 2 << 12, 1, 0x0001, 0x0C | 1 << 8]                # invoke-virtual {v1, v0}, getBytes; move-result-object v1
                + [0x22 | 2 << 8, t["Ljava/math/BigInteger;"], 0x12 | 3 << 8 | 1 << 12]  # new-instance v2; const/4 v3, 1
                + [0x70 | 3 << 12, 2, 0x0132, 0x13 | 3 << 8, 16]            # invoke-direct {v2, v3, v1}, <init>; const/16 v3, 16
                + [0x6E | 2 << 12, 3, 0x0032, 0x0C | 0 << 8, 0x11 | 0 << 8])  # toString(v2, v3); return-object v0
        vm = dexvm.Machine([dexvm.Dex(build_dex(strings, types, protos, methods, t["LCode;"], [(0, 0x9, 5, 1, code)], fields))])
        self.assertEqual(vm.invoke("LCode;", "code", "(Landroid/content/Context;)Ljava/lang/String;", [vm.context], False),
                         b"abc".hex())


class DexVmTests(unittest.TestCase):
    def test_release_code_is_computed_like_java(self):
        self.assertEqual(len(expected()), 20)
        self.assertEqual(dexvm.answer_code(apk(release_dex(), {})), expected())

    def test_day23_analysis_puzzle_goes_through_the_emulator(self):
        puzzle = {"schema": "huntress.mobile.puzzle.v2", "day": 23, "codec": "analysis", "build": "x"}
        self.assertEqual(answer_code(apk(release_dex(), puzzle)), expected())

    def test_step_cap_fails_a_runaway_fast_without_losing_real_apps(self):
        # A real answer-code method runs ~55k steps; the release fixture above proves one
        # still solves under the cap. The cap only bounds a runaway (which wins nothing),
        # and at ~0.9M steps/s it must fail in a few seconds, not the 23 s the old 20M cap
        # cost -- two such apps made day 24's Android Mastery race 52 s and unresolved.
        self.assertLessEqual(dexvm.MAX_STEPS, 5_000_000)
        machine = dexvm.Machine.__new__(dexvm.Machine)
        machine.steps = 0
        machine.classes = {}
        machine.dexes = [SimpleNamespace(classes={})]  # _dex_of falls back to this; goto needs no dex.
        loop = dexvm.Method.__new__(dexvm.Method)
        loop.insns = [0x0028]  # goto 0: a one-instruction infinite loop.
        loop.cls = None
        with self.assertRaises(dexvm.Unsupported):
            machine._run(loop, [])
        self.assertGreater(machine.steps, dexvm.MAX_STEPS)  # It ran to the cap, then stopped.

    def test_platform_calls_outside_the_allow_list_stop_the_run(self):
        with self.assertRaises(dexvm.Unsupported):
            dexvm._platform("Ljava/lang/System;", "currentTimeMillis", "()J", [], None)
        with self.assertRaises(dexvm.Unsupported):
            dexvm._platform("Ljava/io/File;", "<init>", "(Ljava/lang/String;)V", [None, "/x"], None)

    def test_java_integer_semantics(self):
        self.assertEqual(dexvm._binary(3, -7, 2), -3)            # div-int truncates toward zero
        self.assertEqual(dexvm._binary(4, -7, 2), -1)            # rem-int keeps the dividend's sign
        self.assertEqual(dexvm._binary(10, -1, 28), 0xF)         # ushr-int
        self.assertEqual(dexvm._binary(21, -1, 60), 0xF)         # ushr-long
        self.assertEqual(dexvm._binary(0, 0x7FFFFFFF, 1), -0x80000000)
        self.assertEqual(dexvm._java_hash("ANS"), 64966)       # 65*31*31 + 78*31 + 83
        self.assertEqual(dexvm._format("ANS-%016X", [0x1A]), "ANS-000000000000001A")

    def test_x86_64_jni_subset(self):
        # Day 15 libarena.so's shape: mov rax,rdx; movabs rcx,K; add; xor; rol; shr; imul; ret.
        def movabs_rcx(value):
            return b"\x48\xb9" + value.to_bytes(8, "little")
        code = (b"\x48\x89\xd0" + movabs_rcx(K1) + b"\x48\x01\xc8" + movabs_rcx(K2) + b"\x48\x31\xc8"
                + b"\x48\xc1\xc0\x25" + b"\x48\x89\xc1" + b"\x48\xc1\xe9\x15" + b"\x48\x31\xc8"
                + movabs_rcx(K2) + b"\x48\x0f\xaf\xc1" + b"\xc3")
        argument = 0x0123456789ABCDEF
        value = ((argument + K1) & M64) ^ K2
        value = ((value << 37) | (value >> 27)) & M64
        value ^= value >> 21
        value = value * K2 & M64
        self.assertEqual(dexvm.run_x64(code, [0, 0, argument]), value)
        with self.assertRaises(dexvm.Unsupported):
            dexvm.run_x64(b"\x48\x8b\x07\xc3", [0, 0, 0])        # mov rax,[rdi]: memory is never modeled

    def test_x86_64_branches_day25_length_gate(self):
        # Day 25 Mastery's day-16 libarena.so: a Java int narrowed to u16 gates the mix
        # (cmp ecx,0xffff; jle 0; movzx esi,cx; cmp esi,K; jne 0; ...mix...; ret; xor eax,eax; ret).
        def movabs_rcx(value):
            return b"\x48\xb9" + value.to_bytes(8, "little")
        mix = (b"\x48\x89\xd0" + movabs_rcx(K1) + b"\x48\x31\xc8" + b"\x48\xc1\xc0\x2d"
               + movabs_rcx(K2) + b"\x48\x0f\xaf\xc1" + b"\xc3")
        tail = b"\x0f\xb7\xf1" + b"\x81\xfe\xde\x97\x00\x00" + b"\x75" + bytes([len(mix)]) + mix
        code = b"\x81\xf9\xff\xff\x00\x00" + b"\x7e" + bytes([len(tail)]) + tail + b"\x31\xc0\xc3"
        argument = 0x0123456789ABCDEF
        value = argument ^ K1
        value = ((value << 45) | (value >> 19)) & M64
        value = value * K2 & M64
        self.assertEqual(dexvm.run_x64(code, [0, 0, argument, 0x197DE]), value)
        self.assertEqual(dexvm.run_x64(code, [0, 0, argument, 0x97DE]), 0)     # not above 0xffff: jle taken
        self.assertEqual(dexvm.run_x64(code, [0, 0, argument, 0x197DF]), 0)    # wrong low 16 bits: jne taken
        with self.assertRaises(dexvm.Unsupported):
            dexvm.run_x64(b"\x7f\x00\xc3", [0, 0, 0])                          # a branch before any compare

    def test_reflection_reaches_only_app_classes(self):
        # Day 19's maze: Class.forName("a.Maze").getDeclaredMethod("m3", Long.TYPE).invoke(null, j).
        method = SimpleNamespace(cls="La/Maze;", name="m3", params=["J"], ret="J", flags=dexvm.ACC_STATIC)
        calls = []
        vm = SimpleNamespace(
            classes={"La/Maze;": SimpleNamespace(methods={("m3", "(J)J"): method}, superclass=None)},
            invoke=lambda cls, name, sig, args, virtual: calls.append((cls, name, sig, args)) or args[0] + 1)
        maze = dexvm._platform("Ljava/lang/Class;", "forName", "(Ljava/lang/String;)Ljava/lang/Class;", ["a.Maze"], vm)
        found = dexvm._platform("Ljava/lang/Class;", "getDeclaredMethod", "", [maze, "m3", [dexvm.JClass("J")]], vm)
        self.assertEqual(dexvm._platform("Ljava/lang/reflect/Method;", "invoke", "", [found, None, [41]], vm), 42)
        self.assertEqual(calls, [("La/Maze;", "m3", "(J)J", [41])])
        with self.assertRaises(dexvm.Unsupported):
            dexvm._platform("Ljava/lang/Class;", "forName", "", ["java.lang.Runtime"], vm)
        with self.assertRaises(dexvm.Unsupported):
            dexvm._platform("Ljava/lang/Class;", "getDeclaredMethod", "", [maze, "m9", [dexvm.JClass("J")]], vm)

    def test_secondary_dex_from_assets_day20(self):
        # Day 20's module (reused by Day 25 Mastery): getAssets().open("payload.dex"), read in a loop,
        # ByteBuffer.wrap, new InMemoryDexClassLoader(buffer, parent).loadClass(..), reflective invoke.
        payload = release_dex()
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("assets/payload.dex", payload)
            archive.writestr("assets/huge.bin", bytes(dexvm.MAX_ASSET_BYTES + 1))
        vm = dexvm.Machine([], apk=buffer.getvalue())
        call = lambda cls, name, sig, *args: dexvm._platform(cls, name, sig, list(args), vm)
        assets = call("Landroid/content/Context;", "getAssets", "()Landroid/content/res/AssetManager;", vm.context)
        stream = call("Landroid/content/res/AssetManager;", "open", "(Ljava/lang/String;)Ljava/io/InputStream;",
                      assets, "payload.dex")
        chunk, data = [0] * 64, []
        while (count := call("Ljava/io/InputStream;", "read", "([BII)I", stream, chunk, 0, len(chunk))) >= 0:
            data += chunk[:count]
        self.assertEqual(dexvm._bytes(data), payload)
        parent = call("Ljava/lang/Class;", "getClassLoader", "()Ljava/lang/ClassLoader;", dexvm.JClass("LCore;"))
        wrapped = call("Ljava/nio/ByteBuffer;", "wrap", "([BII)Ljava/nio/ByteBuffer;", data, 0, len(data))
        loader = dexvm.Loader()
        call("Ldalvik/system/InMemoryDexClassLoader;", "<init>", "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V",
             loader, wrapped, parent)
        self.assertNotIn("LRelease;", vm.classes)  # Nothing is loaded before loadClass.
        module = call("Ljava/lang/ClassLoader;", "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;", loader, "Release")
        mix = call("Ljava/lang/Class;", "getDeclaredMethod", "", module, "mix", [dexvm.JClass("J")])
        value = call("Ljava/lang/reflect/Method;", "invoke", "", mix, None, [0x0123456789ABCDEF])
        self.assertEqual(f"ANS-{value & M64:016X}", expected())
        self.assertEqual(vm.invoke("LRelease;", "code", "(Landroid/content/Context;)Ljava/lang/String;",
                                   [vm.context], False), expected())
        sink = dexvm.Sink()
        call("Ljava/io/ByteArrayOutputStream;", "write", "([BII)V", sink, [1, -1, 3], 1, 2)
        self.assertEqual(call("Ljava/io/ByteArrayOutputStream;", "toByteArray", "()[B", sink), [-1, 3])
        for name in ("missing.dex", "huge.bin"):  # A missing asset or one past the cap stops the run.
            with self.assertRaises(dexvm.Unsupported):
                call("Landroid/content/res/AssetManager;", "open", "(Ljava/lang/String;)Ljava/io/InputStream;",
                     assets, name)
        with self.assertRaises(dexvm.Unsupported):
            call("Ljava/lang/ClassLoader;", "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;", loader, "Nope")
        with self.assertRaises(dexvm.Unsupported):  # DexClassLoader-style: a path, not bytes in memory.
            call("Ldalvik/system/DexClassLoader;", "<init>", "", dexvm.Loader(), "/data/x.dex", None, None, parent)
        with self.assertRaises(dexvm.Unsupported):  # No APK, no assets.
            dexvm.Context("a.b").asset("payload.dex")

    def test_damaged_asset_is_no_answer_not_a_crash(self):
        # A flipped byte in a stored asset fails its CRC (BadZipFile); like every bounded read
        # (ROBUSTNESS.md workstreams 3 and 4) that is no data, so the run stops with Unsupported.
        content = b"payload-" * 64
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr("assets/payload.dex", content)
        damaged = bytearray(buffer.getvalue())
        at = damaged.index(content)
        damaged[at + 10] ^= 0xFF
        with self.assertRaises(dexvm.Unsupported):
            dexvm.Context("a.b", bytes(damaged)).asset("payload.dex")
        self.assertEqual(dexvm.Context("a.b", buffer.getvalue()).asset("payload.dex"), content)

    def test_jni_names(self):
        self.assertEqual(dexvm.jni_name("Lcom/a_b/C;", "f"), "Java_com_a_1b_C_f")

    def test_not_an_apk(self):
        self.assertIsNone(dexvm.answer_code(b"PK\x05\x06" + bytes(18)))
        self.assertIsNone(dexvm.answer_code(b"plain"))


if __name__ == "__main__":
    unittest.main()
