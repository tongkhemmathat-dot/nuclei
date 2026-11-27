"""VA Scanner: a scan-manager GUI around nuclei. Run: python nuclei_gui.py  (self-check: --test)"""
import html, json, os, shutil, subprocess, sys, textwrap, threading, time, tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# Portable: everything lives next to the app (VA-Scanner.exe or this .py), so the folder can be copied anywhere.
BASE = os.path.dirname(sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__))
NUCLEI = os.path.join(BASE, "nuclei.exe")
TPL = os.path.join(BASE, "nuclei-templates")
REPORTS = os.path.join(BASE, "reports")
# ponytail: fixed category list; add more paths here when needed
CATS = {
    "technologies": r"http\technologies", "misconfiguration": r"http\misconfiguration",
    "exposures": r"http\exposures", "exposed-panels": r"http\exposed-panels",
    "ssl": "ssl", "takeovers": r"http\takeovers", "miscellaneous": r"http\miscellaneous",
    "dns": "dns", "network-detection": r"network\detection", "network-misconfig": r"network\misconfig",
    "network-exposures": r"network\exposures",
    "cves (intrusive)": r"http\cves", "vulnerabilities (intrusive)": r"http\vulnerabilities",
    "default-logins (intrusive)": r"http\default-logins", "iot (intrusive)": r"http\iot",
    "cnvd (intrusive)": r"http\cnvd", "network-cves (intrusive)": r"network\cves",
}
TH = {  # Thai captions shown next to each template set
    "technologies": "เทคโนโลยีที่ใช้", "misconfiguration": "ตั้งค่าผิดพลาด", "exposures": "ข้อมูลรั่วไหล",
    "exposed-panels": "หน้าแอดมินเปิดเผย", "ssl": "ใบรับรอง SSL", "takeovers": "ยึดโดเมนย่อย",
    "miscellaneous": "อื่นๆ", "dns": "ระเบียน DNS", "network-detection": "บริการเครือข่าย",
    "network-misconfig": "เครือข่ายตั้งค่าผิด", "network-exposures": "เครือข่ายข้อมูลรั่ว",
    "cves (intrusive)": "ช่องโหว่ CVE", "vulnerabilities (intrusive)": "ช่องโหว่ทั่วไป",
    "default-logins (intrusive)": "รหัสผ่านเริ่มต้น", "iot (intrusive)": "อุปกรณ์ IoT",
    "cnvd (intrusive)": "ช่องโหว่ CNVD", "network-cves (intrusive)": "CVE เครือข่าย",
}
SEVS = ["info", "low", "medium", "high", "critical"]
SEV_TH = {"info": "ข้อมูล", "low": "ต่ำ", "medium": "กลาง", "high": "สูง", "critical": "วิกฤต"}
SEV_COLOR = {"critical": "#7b1fa2", "high": "#d32f2f", "medium": "#f57c00", "low": "#1976d2", "info": "#607d8b"}
STATUS_COLOR = {"OK": "#2e7d32", "INFO": "#555555", **{s.upper(): c for s, c in SEV_COLOR.items()}}  # TLS table
NOINFO = ["low", "medium", "high", "critical"]
# Modules run independently, in this order: nuclei templates, then each extra module.
MODULES = {"ports": "Port scan / สแกนพอร์ต", "tls": "SSL/TLS (testssl-style)", "headers": "HTTP headers / ตรวจ header"}
# preset -> (template sets, severities, tags, description, modules). Tags filter the sets (set AND tag).
PRESETS = {
    "Quick Scan / ตรวจเร็ว": (["technologies", "ssl", "misconfiguration"], NOINFO, "",
                              "ปลอดภัย · ตรวจพื้นฐาน เทคโนโลยี SSL การตั้งค่า header (~5 นาที)", {"tls", "headers"}),
    "Standard VA / ตรวจมาตรฐาน": (
        ["technologies", "misconfiguration", "exposures", "exposed-panels", "ssl", "takeovers"], NOINFO, "",
        "ปลอดภัย · แนะนำสำหรับงาน VA เว็บทั่วไป", {"tls", "headers"}),
    "Network / ตรวจเครือข่าย": (
        ["dns", "ssl", "network-detection", "network-misconfig", "network-exposures"], NOINFO, "",
        "ปลอดภัย · สแกนพอร์ต DNS SSL บริการบนเซิร์ฟเวอร์", {"ports", "tls"}),
    "Asset Discovery / สำรวจระบบ": (["technologies", "exposed-panels", "network-detection"], SEVS, "",
                                    "ปลอดภัย · ทำบัญชีว่าเป้าหมายใช้อะไรบ้าง (รวม info)", {"ports", "headers"}),
    "Port Scan / สแกนพอร์ต": ([], SEVS, "", "ปลอดภัย · TCP connect scan + banner, ชี้พอร์ตเสี่ยง (RDP SMB DB)", {"ports"}),
    "testssl.sh only / เฉพาะ testssl": ([], SEVS, "", "ปลอดภัย · ไม่รัน nuclei: โปรโตคอล cipher ใบรับรอง ช่องโหว่ TLS + HTTP header",
                                        {"tls", "headers"}),
    "SSL/TLS / ตรวจ SSL/TLS": (["ssl"], SEVS, "", "ปลอดภัย · แบบ testssl.sh: โปรโตคอล cipher ใบรับรอง Heartbleed ROBOT", {"tls"}),
    "HTTP Headers / ตรวจ Header": ([], SEVS, "", "ปลอดภัย · security header, banner, X-Forwarded, cookie, BREACH",
                                   {"headers"}),
    "KEV / ช่องโหว่ที่ถูกโจมตีจริง": (["cves (intrusive)", "network-cves (intrusive)"], NOINFO, "kev",
                                      "INTRUSIVE · CVE ที่มีรายงานการโจมตีจริง ต้องให้หัวหน้าอนุมัติ", set()),
    "WordPress / ตรวจ WordPress": (
        ["technologies", "misconfiguration", "exposures", "cves (intrusive)", "vulnerabilities (intrusive)"],
        NOINFO, "wordpress,wp-plugin", "INTRUSIVE · ปลั๊กอินและธีมที่มีช่องโหว่ ต้องให้หัวหน้าอนุมัติ", {"headers"}),
    "Full Scan / ตรวจเต็ม": (list(CATS), NOINFO, "", "INTRUSIVE · ทุกชุดการตรวจ ใช้เวลานาน ต้องให้หัวหน้าอนุมัติ",
                             set(MODULES)),
}
DEFAULT_PRESET = "Standard VA / ตรวจมาตรฐาน"
# preset -> (when to use, rough duration per target). The checks/modules list is generated from PRESETS.
PRESET_HELP = {
    "Quick Scan / ตรวจเร็ว": ("ตรวจคร่าวๆ ก่อนเริ่มงานจริง หรือเช็คเว็บหลังแก้ไขค่าเสร็จ อยากรู้ผลเร็ว", "~5 นาที"),
    "Standard VA / ตรวจมาตรฐาน": ("งาน VA เว็บไซต์ทั่วไป ครอบคลุมการตั้งค่าผิด ข้อมูลรั่ว หน้าแอดมินที่เปิดเผย "
                                  "และ SSL โดยไม่ยิงช่องโหว่จริง เหมาะเป็นค่าเริ่มต้น", "10-30 นาที"),
    "Network / ตรวจเครือข่าย": ("ตรวจเซิร์ฟเวอร์หรือ IP (ไม่ใช่เว็บ) ดูพอร์ตที่เปิด บริการที่รัน DNS และ SSL", "10-30 นาที"),
    "Asset Discovery / สำรวจระบบ": ("ทำบัญชีทรัพย์สิน: เป้าหมายใช้ซอฟต์แวร์/เวอร์ชันอะไร เปิดพอร์ตอะไร "
                                    "ผลส่วนใหญ่เป็นระดับ info ไม่ใช่ช่องโหว่", "5-20 นาที"),
    "Port Scan / สแกนพอร์ต": ("อยากรู้แค่ว่าเปิดพอร์ตอะไรบ้าง และมีบริการเสี่ยงเช่น RDP SMB ฐานข้อมูล เปิดออกเน็ตหรือไม่",
                              "1-5 นาที (top) · นานขึ้นมากถ้าเลือก all"),
    "testssl.sh only / เฉพาะ testssl": ("ตรวจ SSL/TLS และ HTTP header แบบละเอียดอย่างเดียว ไม่ใช้ nuclei "
                                        "เหมาะกับการยืนยันผลหลังแก้ config เว็บเซิร์ฟเวอร์", "1-3 นาที"),
    "SSL/TLS / ตรวจ SSL/TLS": ("ตรวจใบรับรอง โปรโตคอลเก่า (SSLv3/TLS1.0) cipher อ่อน และช่องโหว่ TLS "
                               "พร้อมให้เกรด A-F", "1-5 นาที"),
    "HTTP Headers / ตรวจ Header": ("ตรวจเฉพาะ security header เช่น HSTS CSP X-Frame-Options, banner ที่บอกเวอร์ชัน, "
                                   "cookie flag ใช้เวลาน้อยมาก", "< 1 นาที"),
    "KEV / ช่องโหว่ที่ถูกโจมตีจริง": ("หาช่องโหว่ CVE ที่อยู่ในรายการ CISA KEV (มีการโจมตีจริงแล้ว) ควรแก้ก่อนเป็นอันดับแรก "
                                      "ส่งคำขอโจมตีจริงไปยังเป้าหมาย", "10-60 นาที"),
    "WordPress / ตรวจ WordPress": ("เว็บที่ใช้ WordPress: หาปลั๊กอิน/ธีมที่มีช่องโหว่ ไฟล์สำคัญที่เปิดเผย", "10-40 นาที"),
    "Full Scan / ตรวจเต็ม": ("ตรวจทุกอย่างที่มี รวมชุดที่ยิงช่องโหว่จริง ใช้เมื่อได้รับอนุมัติให้ทดสอบเต็มรูปแบบ "
                             "และนัดช่วงเวลากับเจ้าของระบบแล้ว", "1 ชั่วโมงขึ้นไป"),
}


def preset_details(p):
    """Plain-language explanation of a preset for the New Scan screen."""
    cats, sevs, tags, desc, mods = PRESETS[p]
    when, dur = PRESET_HELP[p]
    intrusive = desc.startswith("INTRUSIVE")
    lines = [f"ใช้เมื่อ / When:  {when}",
             "ผลกระทบ / Impact:  " + ("⚠ INTRUSIVE — ส่งคำขอทดสอบช่องโหว่จริง อาจทำให้ระบบช้าหรือล่ม ต้องให้หัวหน้าอนุมัติ"
                                     if intrusive else "ปลอดภัย — อ่านอย่างเดียว ไม่พยายามเจาะระบบ")
             + f"      ·  เวลา / Time:  {dur} ต่อเป้าหมาย",
             "ชุดตรวจ nuclei / Checks:  " + (", ".join(TH[c] for c in cats) if cats else "ไม่ใช้ nuclei")
             + (f"  (กรองแท็ก: {tags})" if tags else ""),
             "โมดูลเสริม / Modules:  " + (", ".join(MODULES[m] for m in MODULES if m in mods) or "-")
             + "      ·  รายงานระดับ / Severities:  " + ", ".join(SEV_TH[s] for s in reversed(SEVS) if s in sevs)]
    return "\n".join(lines)


def build_cmd(target_file, cats, sevs, tags, rate, outdir):
    cmd = [NUCLEI, "-l", target_file, "-nc", "-rl", str(rate), "-stats", "-si", "30"]
    for c in cats:
        cmd += ["-t", rf"{TPL}\{CATS[c]}"]
    if sevs:
        cmd += ["-severity", ",".join(sevs)]
    if tags:
        cmd += ["-tags", tags]
    if outdir:  # JSONL is appended per finding, so the Results tab can update while the scan runs
        cmd += ["-o", os.path.join(outdir, "findings.txt"), "-jle", os.path.join(outdir, "findings.jsonl"),
                "-me", os.path.join(outdir, "markdown")]
    return cmd


def tls_endpoint(target):
    """URL/host -> (host, port) for the TLS check, or None for plain-http targets."""
    from urllib.parse import urlsplit
    u = urlsplit(target if "://" in target else "https://" + target)
    if u.scheme == "http" and not u.port:
        return None
    return (u.hostname, u.port or 443) if u.hostname else None


# testssl.sh-style checks, one finding per issue: (id, severity, name, description, remediation)
TLS_ISSUES = {
    "ssl2": ("critical", "SSLv2 enabled (DROWN)", "เซิร์ฟเวอร์รองรับ SSLv2 ซึ่งเลิกใช้แล้วและถูกโจมตีได้ (DROWN)", "ปิด SSLv2"),
    "ssl3": ("high", "SSLv3 enabled (POODLE)", "เซิร์ฟเวอร์รองรับ SSLv3 เสี่ยงต่อ POODLE", "ปิด SSLv3"),
    "tls10": ("medium", "TLS 1.0 enabled (deprecated)", "TLS 1.0 ถูกประกาศเลิกใช้ (RFC 8996), เสี่ยง BEAST", "ปิด TLS 1.0 ใช้ TLS 1.2 ขึ้นไป"),
    "tls11": ("medium", "TLS 1.1 enabled (deprecated)", "TLS 1.1 ถูกประกาศเลิกใช้ (RFC 8996)", "ปิด TLS 1.1 ใช้ TLS 1.2 ขึ้นไป"),
    "no-tls13": ("info", "TLS 1.3 not supported", "ไม่รองรับ TLS 1.3", "เปิดใช้ TLS 1.3"),
    "null-anon": ("high", "NULL / anonymous cipher suites", "รองรับ cipher ที่ไม่เข้ารหัสหรือไม่ยืนยันตัวตน", "ปิด NULL และ anonymous (ADH/AECDH) ciphers"),
    "export": ("high", "EXPORT cipher suites (FREAK/LOGJAM)", "รองรับ EXPORT cipher ที่ถอดรหัสได้ง่าย", "ปิด EXPORT ciphers"),
    "rc4": ("medium", "RC4 cipher suites", "RC4 มีจุดอ่อนทางคริปโต (RFC 7465)", "ปิด RC4"),
    "des": ("medium", "DES/3DES cipher suites (SWEET32)", "cipher บล็อก 64 บิต เสี่ยง SWEET32", "ปิด DES และ 3DES"),
    "weak-dh": ("medium", "Weak Diffie-Hellman key (LOGJAM)", "ใช้ DH key ขนาดน้อยกว่า 2048 บิต", "ใช้ DH 2048 บิตขึ้นไปหรือ ECDHE"),
    "heartbleed": ("critical", "Heartbleed (CVE-2014-0160)", "อ่านหน่วยความจำเซิร์ฟเวอร์ได้ รวมถึง private key", "อัปเดต OpenSSL และเปลี่ยนใบรับรอง/คีย์"),
    "ccs": ("high", "OpenSSL CCS injection (CVE-2014-0224)", "ผู้โจมตีกลางทางถอดรหัสการเชื่อมต่อได้", "อัปเดต OpenSSL"),
    "robot": ("high", "ROBOT (RSA padding oracle)", "ถอดรหัส RSA key exchange ได้", "ปิด cipher ที่ใช้ RSA key exchange (TLS_RSA_*) หรืออัปเดต"),
    "compression": ("medium", "TLS compression enabled (CRIME)", "เปิดการบีบอัด TLS เสี่ยง CRIME", "ปิด TLS compression"),
    "no-scsv": ("low", "TLS_FALLBACK_SCSV not supported", "ไม่ป้องกันการบังคับลดเวอร์ชันโปรโตคอล", "เปิด TLS_FALLBACK_SCSV"),
    "insecure-reneg": ("medium", "Insecure renegotiation", "ไม่รองรับ secure renegotiation (RFC 5746)", "เปิด secure renegotiation"),
    "client-reneg": ("low", "Client-initiated renegotiation (DoS)", "ผู้ใช้เริ่ม renegotiation ได้ เสี่ยง DoS", "ปิด client-initiated renegotiation"),
    "cert-untrusted": ("medium", "Certificate not trusted / hostname mismatch", "ใบรับรองไม่ผ่านการตรวจสอบ", "ใช้ใบรับรองจาก CA ที่เชื่อถือได้ ตรงกับชื่อโดเมน และส่ง chain ครบ"),
    "cert-expired": ("high", "Certificate expired", "ใบรับรองหมดอายุแล้ว", "ต่ออายุใบรับรอง"),
    "cert-expiring": ("low", "Certificate expires within 30 days", "ใบรับรองใกล้หมดอายุ", "ต่ออายุใบรับรอง"),
    "cert-weak-key": ("medium", "Certificate key too small", "public key สั้นกว่า 2048 บิต (RSA) / 256 บิต (EC)", "ออกใบรับรองใหม่ด้วยคีย์ที่ยาวขึ้น"),
    "cert-sha1": ("medium", "SHA-1 signed certificate chain", "ใบรับรองใช้ลายเซ็น SHA-1", "ออกใบรับรองใหม่ที่ใช้ SHA-256 ขึ้นไป"),
    "beast": ("low", "BEAST (CVE-2011-3389)", "TLS 1.0/SSLv3 ใช้ CBC cipher เสี่ยง BEAST (browser รุ่นใหม่ป้องกันฝั่ง client แล้ว)",
              "ปิด TLS 1.0 และ SSLv3"),
    "lucky13": ("low", "LUCKY13 (CVE-2013-0169)", "ใช้ CBC cipher อาจถูกโจมตีแบบ timing (potentially vulnerable)",
                "ใช้ AEAD (GCM / CHACHA20) หรือ TLS 1.3 และจัดลำดับ CBC ไว้ท้าย"),
    "no-hsts": ("low", "HSTS header missing", "ไม่มี Strict-Transport-Security", "เพิ่ม header Strict-Transport-Security"),
    "summary": ("info", "TLS configuration summary", "สรุปโปรโตคอลและใบรับรอง", ""),
}


def tls_findings(host, port, scan):
    """Map one sslyze scan_result to (nuclei-shaped findings, testssl-style table rows).
    Table row = (section, check, result, status) where status is "OK", "INFO" or a severity."""
    import datetime
    out, table = [], []
    ok = lambda a: a is not None and a.status.name == "COMPLETED"

    def row(sec, check_, result, status="INFO"):
        table.append((sec, check_, str(result), status))

    def add(key, extracted=()):
        sev, name, desc, fix = TLS_ISSUES[key]
        out.append({"template-id": f"tls-{key}", "host": f"{host}:{port}", "matched-at": f"{host}:{port}",
                    "extracted-results": list(extracted), "type": "tls",
                    "info": {"name": name, "severity": sev, "description": desc, "remediation": fix,
                             "reference": ["https://testssl.sh/", "https://ssl-config.mozilla.org/"]}})

    def check(sec, label, key, bad, bad_text, good_text="not vulnerable (OK)", extracted=()):
        if bad is None:
            return row(sec, label, "not tested", "INFO")
        if bad:
            add(key, extracted)
        row(sec, label, bad_text if bad else good_text, TLS_ISSUES[key][0].upper() if bad else "OK")

    # --- Protocols
    protos, ciphers, by_proto = [], [], []
    for attr, label, key in (("ssl_2_0", "SSLv2", "ssl2"), ("ssl_3_0", "SSLv3", "ssl3"), ("tls_1_0", "TLS 1.0", "tls10"),
                             ("tls_1_1", "TLS 1.1", "tls11"), ("tls_1_2", "TLS 1.2", None), ("tls_1_3", "TLS 1.3", None)):
        a = getattr(scan, f"{attr}_cipher_suites")
        if not ok(a):
            row("Protocols", label, "not tested", "INFO")
            continue
        acc = a.result.accepted_cipher_suites
        if acc:
            protos.append(label); ciphers += acc; by_proto.append((label, acc))
        if key:
            check("Protocols", label, key, bool(acc), "offered (NOT ok)", "not offered (OK)")
        elif label == "TLS 1.2":
            row("Protocols", label, "offered (OK)" if acc else "not offered", "OK" if acc else "MEDIUM")
        else:
            row("Protocols", label, "offered (OK)" if acc else "not offered", "OK" if acc else "INFO")
            if protos and not acc:
                add("no-tls13")

    # --- Cipher categories
    def names(pred):
        return sorted({c.cipher_suite.name for c in ciphers if pred(c)})

    def weak_dh(c):
        return c.ephemeral_key is not None and c.ephemeral_key.type_name == "DH" and c.ephemeral_key.size < 2048

    cats = (("NULL / anonymous ciphers", "null-anon", lambda c: c.cipher_suite.is_anonymous or "NULL" in c.cipher_suite.name),
            ("EXPORT ciphers", "export", lambda c: "EXPORT" in c.cipher_suite.name),
            ("RC4 ciphers", "rc4", lambda c: "RC4" in c.cipher_suite.name),
            ("DES / 3DES ciphers", "des", lambda c: "DES" in c.cipher_suite.name),
            ("DH key < 2048 bits", "weak-dh", weak_dh))
    weak = set()
    for label, key, pred in cats:
        hit = names(pred)
        weak |= set(hit)
        check("Cipher categories", label, key, bool(hit), ", ".join(hit), "not offered (OK)", hit)
    # TLS 1.3 suites (TLS_AES_*, TLS_CHACHA20_*) are always forward-secret
    no_fs = names(lambda c: c.ephemeral_key is None and not c.cipher_suite.name.startswith(("TLS_AES", "TLS_CHACHA20")))
    row("Cipher categories", "Forward secrecy", f"{len(no_fs)} cipher(s) without FS: {', '.join(no_fs)}" if no_fs
        else "all ciphers offer FS (OK)", "LOW" if no_fs else "OK")

    # --- Vulnerabilities
    def res(a):
        return a.result if ok(a) else None

    hb, ccs, rb, cmp, scsv, ren, ed = (res(scan.heartbleed), res(scan.openssl_ccs_injection), res(scan.robot),
                                       res(scan.tls_compression), res(scan.tls_fallback_scsv),
                                       res(scan.session_renegotiation), res(scan.tls_1_3_early_data))
    V = "Vulnerabilities"
    check(V, "Heartbleed (CVE-2014-0160)", "heartbleed", hb and hb.is_vulnerable_to_heartbleed, "VULNERABLE")
    check(V, "CCS injection (CVE-2014-0224)", "ccs", ccs and ccs.is_vulnerable_to_ccs_injection, "VULNERABLE")
    check(V, "ROBOT", "robot", rb and rb.robot_result.name.startswith("VULNERABLE"),
          f"VULNERABLE ({rb.robot_result.name if rb else ''})", extracted=[rb.robot_result.name] if rb else [])
    check(V, "CRIME (TLS compression)", "compression", cmp and cmp.supports_compression, "VULNERABLE (compression on)")
    check(V, "Secure renegotiation (RFC 5746)", "insecure-reneg", ren and not ren.supports_secure_renegotiation,
          "NOT supported", "supported (OK)")
    check(V, "Client-initiated renegotiation", "client-reneg", ren and ren.is_vulnerable_to_client_renegotiation_dos,
          "VULNERABLE (DoS)", "not vulnerable (OK)")
    downgrade = bool(set(protos) & {"SSLv3", "TLS 1.0", "TLS 1.1"})
    check(V, "TLS_FALLBACK_SCSV (downgrade)", "no-scsv", scsv and downgrade and not scsv.supports_fallback_scsv,
          "NOT supported", "supported (OK)" if scsv and scsv.supports_fallback_scsv else "no old protocol to downgrade to (OK)")
    # DROWN/POODLE rows mirror the protocol result; the finding itself was already added under Protocols
    for label, attr, proto in (("DROWN (SSLv2)", "ssl_2_0", "SSLv2"), ("POODLE (SSLv3)", "ssl_3_0", "SSLv3")):
        if not ok(getattr(scan, f"{attr}_cipher_suites")):
            row(V, label, "not tested", "INFO")
        else:
            row(V, label, "VULNERABLE" if proto in protos else "not vulnerable (OK)",
                TLS_ISSUES["ssl2" if proto == "SSLv2" else "ssl3"][0].upper() if proto in protos else "OK")
    # testssl.sh -U rows. SWEET32/FREAK/LOGJAM/RC4 mirror the cipher categories (finding already added there)
    def mirror(label, hit, key, bad="VULNERABLE"):
        row(V, label, f"{bad}: {', '.join(hit)}" if hit else "not vulnerable (OK)",
            TLS_ISSUES[key][0].upper() if hit else "OK")
    mirror("SWEET32 (CVE-2016-2183)", names(lambda c: any(t in c.cipher_suite.name for t in ("3DES", "DES_EDE", "IDEA"))), "des")
    mirror("FREAK (CVE-2015-0204)", names(lambda c: "EXPORT" in c.cipher_suite.name and "_RSA_" in c.cipher_suite.name
                                          and "DH" not in c.cipher_suite.name), "export")
    mirror("LOGJAM (CVE-2015-4000)", names(lambda c: ("EXPORT" in c.cipher_suite.name and "DH" in c.cipher_suite.name)
                                           or (weak_dh(c) and c.ephemeral_key.size <= 1024)), "weak-dh")
    mirror("RC4 (CVE-2013-2566, CVE-2015-2808)", names(lambda c: "RC4" in c.cipher_suite.name), "rc4")
    old_cbc = sorted({c.cipher_suite.name for lbl, acc in by_proto if lbl in ("SSLv3", "TLS 1.0")
                      for c in acc if "CBC" in c.cipher_suite.name})
    check(V, "BEAST (CVE-2011-3389)", "beast", bool(old_cbc) if by_proto else None,
          f"VULNERABLE ({len(old_cbc)} CBC cipher(s) on SSLv3/TLS 1.0)", "not vulnerable (OK)", old_cbc)
    cbc = names(lambda c: "CBC" in c.cipher_suite.name)
    check(V, "LUCKY13 (CVE-2013-0169)", "lucky13", bool(cbc) if by_proto else None,
          f"potentially VULNERABLE ({len(cbc)} CBC cipher(s))", "not vulnerable (OK)", cbc)
    if ed:
        row(V, "TLS 1.3 early data (0-RTT)", "supported (replay risk)" if ed.supports_early_data else "not supported (OK)",
            "LOW" if ed.supports_early_data else "OK")

    # --- Certificate (server defaults)
    C = "Certificate"
    summary = [f"Protocols: {', '.join(protos) or 'none'}", f"Accepted cipher suites: {len({c.cipher_suite.name for c in ciphers})}"]
    cert = {"bits": 0, "ec": False, "untrusted": False, "expired": False, "sha1": False}  # inputs for the grade
    ci = res(scan.certificate_info)
    if ci and ci.certificate_deployments:
        d = ci.certificate_deployments[0]
        leaf = d.received_certificate_chain[0]
        key = leaf.public_key()
        kname = type(key).__name__.replace("PublicKey", "").replace("_", "")
        bits = getattr(key, "key_size", 0)
        end, start = leaf.not_valid_after_utc, leaf.not_valid_before_utc
        days = (end - datetime.datetime.now(datetime.timezone.utc)).days
        try:
            from cryptography.x509 import SubjectAlternativeName, DNSName
            san = leaf.extensions.get_extension_for_class(SubjectAlternativeName).value.get_values_for_type(DNSName)
        except Exception:
            san = []
        row(C, "Subject", leaf.subject.rfc4514_string())
        row(C, "Subject Alt Names", " ".join(san) or "(none)", "INFO" if san else "MEDIUM")
        row(C, "Issuer", leaf.issuer.rfc4514_string())
        row(C, "Serial", format(leaf.serial_number, "X"))
        row(C, "Signature algorithm", getattr(leaf.signature_hash_algorithm, "name", "?"),
            "MEDIUM" if d.verified_chain_has_sha1_signature else "OK")
        if d.verified_chain_has_sha1_signature:
            add("cert-sha1")
        weak_key = bool(bits) and bits < (256 if "Elliptic" in type(key).__name__ else 2048)
        check(C, "Key", "cert-weak-key", weak_key, f"{kname} {bits} bits (too small)", f"{kname} {bits} bits (OK)",
              [f"{kname} {bits} bits"])
        row(C, "Valid from", f"{start:%Y-%m-%d %H:%M} UTC")
        if days < 0:
            add("cert-expired", [f"Expired: {end:%Y-%m-%d}"])
            st, txt = "HIGH", f"EXPIRED {-days} days ago"
        elif days < 30:
            add("cert-expiring", [f"Expires: {end:%Y-%m-%d} ({days} days)"])
            st, txt = "LOW", f"expires in {days} days"
        else:
            st, txt = "OK", f"{days} days left (OK)"
        row(C, "Valid until", f"{end:%Y-%m-%d %H:%M} UTC  ({txt})", st)
        errors = []
        for p in d.path_validation_results:
            e = p.validation_error
            row(C, f"Trust ({p.trust_store.name})", f"NOT trusted: {e}" if e else "trusted (OK)", "MEDIUM" if e else "OK")
            if e:
                errors.append(str(e))
        if errors:
            add("cert-untrusted", sorted(set(errors)))
        cert.update(bits=bits, ec="Elliptic" in type(key).__name__, untrusted=bool(errors), expired=days < 0,
                    sha1=bool(d.verified_chain_has_sha1_signature))
        row(C, "Chain order", "valid (OK)" if d.received_chain_has_valid_order else "incorrect order",
            "OK" if d.received_chain_has_valid_order else "LOW")
        row(C, "Chain length (sent)", len(d.received_certificate_chain))
        row(C, "OCSP stapling", "offered (OK)" if d.ocsp_response else "not offered", "OK" if d.ocsp_response else "INFO")
        row(C, "OCSP must-staple", "yes" if d.leaf_certificate_has_must_staple_extension else "no")
        row(C, "Certificate Transparency (SCTs)", d.leaf_certificate_signed_certificate_timestamps_count)
        row(C, "Extended Validation (EV)", "yes" if d.leaf_certificate_is_ev else "no")
        summary += [f"Subject: {leaf.subject.rfc4514_string()}", f"Issuer: {leaf.issuer.rfc4514_string()}",
                    f"Valid until: {end:%Y-%m-%d} ({days} days)", f"Key: {kname} {bits} bits"]
    elif scan.certificate_info is not None:  # surface why, instead of silently reporting "no cert issues"
        why = scan.certificate_info.error_trace and "".join(scan.certificate_info.error_trace.format())[-400:]
        row(C, "Certificate check", f"FAILED: {scan.certificate_info.status.name} {why or ''}", "INFO")
        summary.append(f"Certificate check failed: {scan.certificate_info.status.name} {why or ''}")

    # --- HTTP headers / key exchange
    hh = res(scan.http_headers)
    hsts_age = 0
    if hh and not hh.http_error_trace:
        h = hh.strict_transport_security_header
        hsts_age = (h.max_age or 0) if h else 0
        good = (f"max-age={h.max_age}{'; includeSubDomains' if h.include_subdomains else ''}"
                f"{'; preload' if h.preload else ''} (OK)") if h else ""
        check("HTTP headers", "Strict-Transport-Security", "no-hsts", h is None, "not offered", good)
    else:
        row("HTTP headers", "Strict-Transport-Security", "could not get HTTP response", "INFO")
    ec = res(scan.elliptic_curves)
    if ec and ec.supported_curves:
        row("Key exchange", "Elliptic curves", " ".join(c.name for c in ec.supported_curves))

    # --- Every accepted cipher, per protocol (like testssl -E)
    cinfo = []
    for label, acc in by_proto:
        for c in sorted(acc, key=lambda c: (-c.cipher_suite.key_size, c.cipher_suite.name)):
            cs, ek = c.cipher_suite, c.ephemeral_key
            strength, st = cipher_strength(cs.name, cs.key_size, cs.is_anonymous, ek is not None or label == "TLS 1.3")
            cinfo.append({"protocol": label, "name": cs.name, "openssl": cs.openssl_name, "bits": cs.key_size,
                          "kx": f"{ek.type_name} {ek.size}" if ek else ("(TLS 1.3)" if label == "TLS 1.3" else "RSA"),
                          "kx_type": ek.type_name if ek else "", "kx_size": ek.size if ek else 0,
                          "strength": strength, "status": st})

    # --- Overall grade (SSL Labs method, as testssl.sh --rating)
    grade = tls_grade(protos, cinfo, cert, {
        "heartbleed": bool(hb and hb.is_vulnerable_to_heartbleed), "ccs": bool(ccs and ccs.is_vulnerable_to_ccs_injection),
        "robot": bool(rb and rb.robot_result.name.startswith("VULNERABLE")), "compression": bool(cmp and cmp.supports_compression),
        "insecure_reneg": bool(ren and not ren.supports_secure_renegotiation), "hsts_age": hsts_age,
        "no_scsv": bool(scsv and downgrade and not scsv.supports_fallback_scsv)})
    g = grade["grade"]
    G = "Rating"
    rating = [(G, "Overall grade", g + (f"  (would be {grade['grade_ignoring_trust']} if the certificate were trusted)"
                                        if g == "T" else ""), GRADE_STATUS.get(g, "INFO"))]
    if "score" in grade:
        rating += [(G, "Score", f"{grade['score']} / 100", "INFO"),
                   (G, "Protocol support (30%)", f"{grade['protocol']:g} / 100", "INFO"),
                   (G, "Key exchange (30%)", f"{grade['key_exchange']:g} / 100", "INFO"),
                   (G, "Cipher strength (40%)", f"{grade['cipher']:g} / 100", "INFO")]
    rating += [(G, f"Grade cap {cap}", why, GRADE_STATUS.get(cap, "INFO")) for cap, why in grade["caps"]]
    table[:0] = rating
    summary.insert(0, f"Grade: {g}")
    add("summary", summary)
    return out, {"grade": grade, "rows": table, "ciphers": cinfo}


GRADES = ["A+", "A", "B", "C", "D", "E", "F"]
GRADE_STATUS = {"A+": "OK", "A": "OK", "B": "LOW", "C": "MEDIUM", "D": "HIGH", "E": "HIGH", "F": "CRITICAL", "T": "HIGH"}
GRADE_COLOR = {"A+": "#1b5e20", "A": "#2e7d32", "B": "#9e9d24", "C": "#f57c00", "D": "#e64a19", "E": "#d32f2f",
               "F": "#b71c1c", "T": "#b71c1c", "-": "#757575"}


def cipher_strength(name, bits, anon, fs):
    """testssl-style label for one cipher suite -> (label, table status)."""
    if anon or "NULL" in name or "EXPORT" in name or "RC4" in name or (bits and bits < 112) or "_DES_" in name:
        return "insecure", "HIGH"
    if "3DES" in name or "DES_EDE" in name:
        return "weak (64-bit block, SWEET32)", "MEDIUM"
    if not fs:
        return "weak (no forward secrecy)", "LOW"
    if "CBC" in name:
        return "OK (CBC, not AEAD)", "OK"
    return "strong", "OK"


def tls_grade(protos, cinfo, cert, f):
    """SSL Labs Server Rating Guide (2009r) score + caps, as used by testssl.sh --rating.
    cert: bits, ec, untrusted, expired, sha1.  f: heartbleed, ccs, robot, compression, insecure_reneg, hsts_age, no_scsv."""
    if not protos or not cinfo:
        return {"grade": "-", "caps": [("-", "no TLS connection / no ciphers")]}
    ps = {"SSLv2": 0, "SSLv3": 80, "TLS 1.0": 90, "TLS 1.1": 95, "TLS 1.2": 100, "TLS 1.3": 100}
    p = (max(ps[x] for x in protos) + min(ps[x] for x in protos)) / 2
    kx_score = lambda b: 20 if b < 512 else 40 if b < 1024 else 80 if b < 2048 else 90 if b < 4096 else 100
    # EC keys are scored by their RSA-equivalent strength (NIST SP 800-57)
    rsa_eq = (3072 if cert["bits"] <= 256 else 7680 if cert["bits"] <= 384 else 15360) if cert["ec"] else cert["bits"]
    kx_bits = [b for b in [rsa_eq] + [c["kx_size"] for c in cinfo if c["kx_type"] == "DH"] if b]
    k = kx_score(min(kx_bits)) if kx_bits else 0
    c_score = lambda b: 0 if b == 0 else 20 if b < 128 else 80 if b < 256 else 100
    c = (c_score(max(x["bits"] for x in cinfo)) + c_score(min(x["bits"] for x in cinfo))) / 2
    score = round(0.3 * p + 0.3 * k + 0.4 * c)
    grade = "A" if score >= 80 else "B" if score >= 65 else "C" if score >= 50 else "D" if score >= 35 else "E" if score >= 20 else "F"
    names = [x["name"] for x in cinfo]
    has = lambda *s: any(any(t in n for t in s) for n in names)
    dh = [x["kx_size"] for x in cinfo if x["kx_type"] == "DH"]
    caps = [(cap, why) for cap, why, hit in (
        ("F", "SSLv2 offered (DROWN)", "SSLv2" in protos),
        ("F", "Heartbleed vulnerable", f["heartbleed"]),
        ("F", "OpenSSL CCS injection vulnerable", f["ccs"]),
        ("F", "ROBOT vulnerable", f["robot"]),
        ("F", "insecure renegotiation", f["insecure_reneg"]),
        ("F", "EXPORT, NULL or anonymous cipher suites offered", has("EXPORT", "NULL", "_anon_")),
        ("F", "DH parameters < 1024 bits (LOGJAM)", bool(dh) and min(dh) < 1024),
        ("C", "SSLv3 offered (POODLE)", "SSLv3" in protos),
        ("C", "TLS compression enabled (CRIME)", f["compression"]),
        ("C", "3DES / DES cipher suites offered (SWEET32)", has("DES")),
        ("C", "TLS 1.2 not supported", "TLS 1.2" not in protos and "TLS 1.3" not in protos),
        ("B", "RC4 cipher suites offered", has("RC4")),
        ("B", "TLS 1.0 / TLS 1.1 offered", bool({"TLS 1.0", "TLS 1.1"} & set(protos))),
        ("B", "cipher suites without forward secrecy offered", any("forward" in x["strength"] for x in cinfo)),
        ("B", "no AEAD cipher suites (GCM / CHACHA20 / TLS 1.3)", not has("GCM", "CHACHA20", "CCM") and "TLS 1.3" not in protos),
        ("B", "DH parameters < 2048 bits", bool(dh) and min(dh) < 2048),
        ("B", "certificate key too small", bool(cert["bits"]) and cert["bits"] < (256 if cert["ec"] else 2048)),
        ("B", "SHA-1 signed certificate chain", cert["sha1"]),
        ("B", "TLS_FALLBACK_SCSV not supported (downgrade possible)", f["no_scsv"]),
        ("A", "TLS 1.3 not supported (no A+)", "TLS 1.3" not in protos),
        ("A", "HSTS missing or max-age < 180 days (no A+)", f["hsts_age"] < 15552000),
    ) if hit]
    for cap, _ in caps:
        if GRADES.index(cap) > GRADES.index(grade):
            grade = cap
    if grade == "A" and not any(cap in ("A", "B", "C", "F") for cap, _ in caps):
        grade = "A+"
    out = {"score": score, "protocol": p, "key_exchange": k, "cipher": c, "caps": caps, "grade": grade}
    if cert["untrusted"] or cert["expired"]:
        out.update(grade="T", grade_ignoring_trust=grade)
        caps.insert(0, ("T", "certificate not trusted or expired"))
    return out


def tls_scan(targets, log):
    """Run sslyze against every TLS endpoint. Returns (findings, {host:port: table rows})."""
    from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation
    from sslyze.errors import ServerHostnameCouldNotBeResolved
    reqs = {}
    for t in targets:
        ep = tls_endpoint(t)
        if not ep:
            log(f"[tls] skip {t} (http, no TLS)\n")
            continue
        try:
            reqs[ep] = ServerScanRequest(server_location=ServerNetworkLocation(*ep))
        except ServerHostnameCouldNotBeResolved:
            log(f"[tls] cannot resolve {ep[0]}\n")
    found, tables = [], {}
    if not reqs:
        return found, tables
    scanner = Scanner()
    scanner.queue_scans(list(reqs.values()))
    for r in scanner.get_results():
        loc = f"{r.server_location.hostname}:{r.server_location.port}"
        if r.connectivity_error_trace or r.scan_result is None:
            log(f"[tls] {loc}: cannot connect over TLS\n")
            tables[loc] = {"grade": {"grade": "-", "caps": []}, "ciphers": [],
                           "rows": [("Connectivity", "TLS handshake", "cannot connect over TLS", "INFO")]}
            continue
        f, tables[loc] = tls_findings(r.server_location.hostname, r.server_location.port, r.scan_result)
        log(f"[tls] {loc}: {len(f) - 1} issue(s)\n")
        found += f
    return found, tables


def finding(tid, where, sev, name, desc, fix, extracted=(), ref=()):
    """One nuclei-shaped finding, so every module shows up in Vulnerabilities / Hosts / HTML the same way."""
    return {"template-id": tid, "host": where, "matched-at": where, "extracted-results": list(extracted), "type": "va",
            "info": {"name": name, "severity": sev, "description": desc, "remediation": fix, "reference": list(ref)}}


def target_host(t):
    from urllib.parse import urlsplit
    return urlsplit(t if "://" in t else "//" + t).hostname


# ---------- Port scan ----------
# port -> (service, severity when exposed to the internet, why)
PORTS = {
    21: ("FTP", "medium", "FTP ส่งรหัสผ่านแบบไม่เข้ารหัส ใช้ SFTP/FTPS แทน"), 22: ("SSH", "info", "จำกัด IP และใช้ key แทนรหัสผ่าน"),
    23: ("Telnet", "high", "Telnet ไม่เข้ารหัส ควรปิด"), 25: ("SMTP", "info", "ตรวจว่าไม่เป็น open relay"),
    53: ("DNS", "info", "ตรวจว่าไม่เปิด recursion ให้ภายนอก"), 80: ("HTTP", "info", "ควร redirect ไป HTTPS"),
    81: ("HTTP-alt", "info", "พอร์ตเว็บเสริม"), 110: ("POP3", "low", "ไม่เข้ารหัส ใช้ POP3S"), 111: ("RPCbind", "medium", "ไม่ควรเปิดออก Internet"),
    135: ("MS-RPC", "high", "Windows RPC ไม่ควรเปิดออก Internet"), 139: ("NetBIOS", "high", "Windows file sharing ไม่ควรเปิดออก Internet"),
    143: ("IMAP", "low", "ไม่เข้ารหัส ใช้ IMAPS"), 389: ("LDAP", "medium", "directory service ไม่ควรเปิดออก Internet"),
    443: ("HTTPS", "info", "เว็บ HTTPS"), 445: ("SMB", "high", "SMB ถูกใช้โดย ransomware/EternalBlue ไม่ควรเปิดออก Internet"),
    465: ("SMTPS", "info", "mail submission"), 502: ("Modbus", "high", "ICS/SCADA ไม่ควรเปิดออก Internet"),
    587: ("SMTP-sub", "info", "mail submission"), 636: ("LDAPS", "medium", "directory service ไม่ควรเปิดออก Internet"),
    873: ("rsync", "medium", "อาจเข้าถึงไฟล์ได้โดยไม่ยืนยันตัวตน"), 993: ("IMAPS", "info", "mail"), 995: ("POP3S", "info", "mail"),
    1433: ("MSSQL", "high", "ฐานข้อมูลไม่ควรเปิดออก Internet"), 1521: ("Oracle", "high", "ฐานข้อมูลไม่ควรเปิดออก Internet"),
    1723: ("PPTP", "medium", "PPTP VPN เข้ารหัสอ่อน"), 2049: ("NFS", "high", "แชร์ไฟล์ไม่ควรเปิดออก Internet"),
    2082: ("cPanel", "medium", "หน้าแอดมิน hosting"), 2083: ("cPanel-SSL", "medium", "หน้าแอดมิน hosting"),
    2086: ("WHM", "medium", "หน้าแอดมิน hosting"), 2087: ("WHM-SSL", "medium", "หน้าแอดมิน hosting"),
    2375: ("Docker API", "critical", "Docker API ไม่มีรหัส = ยึดเครื่องได้ทันที"), 2376: ("Docker TLS", "medium", "Docker API"),
    3000: ("HTTP-dev", "info", "พอร์ตเว็บ/dev"), 3306: ("MySQL", "high", "ฐานข้อมูลไม่ควรเปิดออก Internet"),
    3389: ("RDP", "high", "RDP ถูก brute-force และใช้ปล่อย ransomware บ่อยที่สุด ให้เข้าผ่าน VPN"),
    5000: ("HTTP-alt", "info", "พอร์ตเว็บเสริม"), 5432: ("PostgreSQL", "high", "ฐานข้อมูลไม่ควรเปิดออก Internet"),
    5601: ("Kibana", "medium", "dashboard อาจไม่มีรหัส"), 5672: ("AMQP", "low", "message queue"),
    5900: ("VNC", "high", "remote desktop มักใช้รหัสอ่อน"), 5985: ("WinRM", "medium", "Windows remote management"),
    5986: ("WinRM-SSL", "medium", "Windows remote management"), 6379: ("Redis", "high", "Redis มักไม่มีรหัส ยึดเครื่องได้"),
    6443: ("Kubernetes API", "medium", "cluster API"), 7001: ("WebLogic", "medium", "มีประวัติ RCE หลายตัว"),
    8000: ("HTTP-alt", "info", "พอร์ตเว็บเสริม"), 8009: ("AJP", "high", "Ghostcat (CVE-2020-1938)"),
    8080: ("HTTP-proxy", "info", "พอร์ตเว็บเสริม ตรวจว่าเป็นหน้าแอดมินหรือไม่"), 8081: ("HTTP-alt", "info", "พอร์ตเว็บเสริม"),
    8443: ("HTTPS-alt", "info", "พอร์ตเว็บเสริม"), 8888: ("HTTP-alt", "info", "พอร์ตเว็บเสริม"), 9000: ("HTTP-alt", "info", "พอร์ตเว็บเสริม"),
    9090: ("HTTP-alt", "info", "พอร์ตเว็บเสริม"), 9200: ("Elasticsearch", "high", "ข้อมูลอาจอ่านได้โดยไม่มีรหัส"),
    10000: ("Webmin", "medium", "หน้าแอดมิน server"), 10250: ("Kubelet", "high", "อาจสั่งรันคำสั่งใน container ได้"),
    11211: ("Memcached", "high", "ไม่มีรหัส และใช้ทำ DDoS amplification"), 15672: ("RabbitMQ mgmt", "medium", "หน้าแอดมิน"),
    27017: ("MongoDB", "high", "ฐานข้อมูลไม่ควรเปิดออก Internet"), 47001: ("WinRM", "medium", "Windows remote management"),
    **{p: ("MS-RPC dyn", "medium", "Windows RPC dynamic port ไม่ควรเปิดออก Internet") for p in range(49152, 49158)},
}


def parse_ports(spec):
    """'top' / 'all' / '21,80,8000-8100' (mixable: 'top,8081') -> sorted ports. Raises ValueError on bad input."""
    out = set()
    for part in (spec or "top").replace(" ", "").lower().split(","):
        if part in ("top", ""):
            out |= set(PORTS)
        elif part == "all":
            out |= set(range(1, 65536))
        else:
            a, _, b = part.partition("-")
            a, b = int(a), int(b or a)
            if not 1 <= a <= b <= 65535:
                raise ValueError(f"bad port range: {part}")
            out |= set(range(a, b + 1))
    return sorted(out)


def port_scan(targets, spec, log, stopped=lambda: False):
    """TCP connect scan + first-line banner. Returns (findings, {host: [port rows]})."""
    import socket
    from concurrent.futures import ThreadPoolExecutor
    ports = parse_ports(spec)
    hosts = []
    for h in dict.fromkeys(filter(None, map(target_host, targets))):
        try:
            socket.getaddrinfo(h, None); hosts.append(h)
        except OSError:
            log(f"[ports] cannot resolve {h}\n")

    def probe(hp):
        if stopped():
            return None
        try:
            with socket.create_connection(hp, timeout=2) as s:
                s.settimeout(1.5)
                try:
                    b = s.recv(256)
                except OSError:
                    b = b""
        except OSError:
            return None
        text = "".join(ch if ch.isprintable() else " " for ch in b.decode("latin-1"))
        return hp, " ".join(text.split())[:160]

    # ponytail: one pass, 100 threads, 2s timeout. An IPS that drops bursts can hide ports; re-run to confirm.
    log(f"[ports] {len(hosts)} host(s) x {len(ports)} port(s) ...\n")
    with ThreadPoolExecutor(100) as ex:
        hits = [r for r in ex.map(probe, [(h, p) for h in hosts for p in ports]) if r]
    found, tables = [], {h: [] for h in hosts}
    for (h, p), banner in sorted(hits):
        svc, sev, why = PORTS.get(p, ("unknown", "info", "พอร์ตเปิด ตรวจว่าจำเป็นต้องเปิดหรือไม่"))
        tables[h].append({"port": p, "service": svc, "banner": banner, "severity": sev, "note": why})
        found.append(finding(f"port-{p}", f"{h}:{p}", sev, f"{svc} exposed ({p}/tcp)", f"พอร์ต {p}/tcp ({svc}) เปิดอยู่: {why}",
                             "ปิดพอร์ตที่ firewall หรือจำกัด IP ที่เข้าถึงได้ / ให้เข้าผ่าน VPN" if sev != "info" else "",
                             [banner] if banner else []))
        log(f"[ports] {h}:{p} open {svc} {banner}\n")
    return found, tables


# ---------- HTTP headers (testssl.sh -h style) ----------
HDR_ISSUES = {
    "hsts": ("low", "HSTS header missing", "ไม่มี Strict-Transport-Security เสี่ยง SSL stripping", "เพิ่ม Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    "csp": ("low", "Content-Security-Policy missing", "ไม่มี CSP ช่วยลดผลกระทบ XSS", "กำหนด Content-Security-Policy"),
    "xfo": ("low", "Clickjacking protection missing", "ไม่มี X-Frame-Options หรือ CSP frame-ancestors", "เพิ่ม X-Frame-Options: DENY/SAMEORIGIN หรือ CSP frame-ancestors"),
    "xcto": ("low", "X-Content-Type-Options missing", "ไม่มี X-Content-Type-Options: nosniff", "เพิ่ม X-Content-Type-Options: nosniff"),
    "referrer": ("info", "Referrer-Policy missing", "ไม่ได้กำหนด Referrer-Policy", "เพิ่ม Referrer-Policy: strict-origin-when-cross-origin"),
    "permissions": ("info", "Permissions-Policy missing", "ไม่ได้กำหนด Permissions-Policy", "กำหนด Permissions-Policy"),
    "server-version": ("low", "Server banner discloses version", "header Server เปิดเผยชื่อ/เวอร์ชันซอฟต์แวร์", "ซ่อนเวอร์ชันใน header Server"),
    "tech-banner": ("low", "Application banner disclosed", "header เปิดเผยเทคโนโลยี/เวอร์ชัน (X-Powered-By, X-AspNet-Version ...)", "ลบ header เหล่านี้ออก"),
    "proxy-banner": ("info", "Reverse proxy / X-Forwarded headers disclosed", "header จาก proxy/cache เปิดเผยโครงสร้างภายใน", "ลบ header ที่ proxy เพิ่มเข้ามาก่อนส่งให้ผู้ใช้"),
    "internal-ip": ("low", "Internal IP address disclosed in headers", "header เปิดเผย IP ภายในองค์กร", "ลบ/แก้ header ที่มี IP ภายใน"),
    "xfh-reflect": ("medium", "Host header injection (X-Forwarded-Host reflected)", "ค่า X-Forwarded-Host ที่ส่งไปถูกสะท้อนกลับ เสี่ยง cache poisoning / password-reset poisoning",
                    "ไม่เชื่อ X-Forwarded-Host จากผู้ใช้ ใช้ชื่อโดเมนที่ตั้งค่าไว้"),
    "cookie-flags": ("low", "Cookie without Secure / HttpOnly / SameSite", "cookie ไม่ได้ตั้ง flag ป้องกัน", "ตั้ง Secure; HttpOnly; SameSite ให้ cookie"),
    "cors": ("low", "CORS allows any origin", "Access-Control-Allow-Origin: *", "จำกัด origin ที่อนุญาต"),
    "breach": ("low", "HTTP compression (BREACH, CVE-2013-3587)", "เปิด HTTP compression อาจเสี่ยง BREACH หากหน้ามี secret", "ปิด compression สำหรับหน้าที่มี token/secret"),
}
TECH_HEADERS = ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-runtime", "x-version", "x-owa-version")
PROXY_HEADERS = ("via", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-server", "x-real-ip",
                 "x-cache", "x-cache-hits", "x-varnish", "x-served-by", "x-backend-server", "x-proxy-cache", "x-upstream")
PROBE_HOST = "va-scanner-probe.invalid"


def header_findings(url, status, hdrs, cookies, reflected, compressed):
    """hdrs: {lowercase name: value}. Returns (findings, testssl-style rows)."""
    import re
    out, rows = [], [("Response", "HTTP status", str(status), "INFO")]
    if hdrs.get("location"):
        rows.append(("Response", "Location", hdrs["location"], "INFO"))

    def add(key, extracted=()):
        sev, name, desc, fix = HDR_ISSUES[key]
        out.append(finding(f"hdr-{key}", url, sev, name, desc, fix, extracted, ["https://owasp.org/www-project-secure-headers/"]))

    def check(sec, label, key, bad, bad_text, good_text, extracted=()):
        if bad:
            add(key, extracted)
        rows.append((sec, label, bad_text if bad else good_text, HDR_ISSUES[key][0].upper() if bad else "OK"))

    S, csp = "Security headers", hdrs.get("content-security-policy", "")
    if url.startswith("https"):
        h = hdrs.get("strict-transport-security", "")
        check(S, "Strict-Transport-Security", "hsts", not h, "not offered", f"{h} (OK)")
    check(S, "Content-Security-Policy", "csp", not csp, "not offered", f"{csp[:200]} (OK)")
    xfo = hdrs.get("x-frame-options", "")
    check(S, "X-Frame-Options / frame-ancestors", "xfo", not xfo and "frame-ancestors" not in csp, "not offered",
          f"{xfo or 'CSP frame-ancestors'} (OK)")
    x = hdrs.get("x-content-type-options", "")
    check(S, "X-Content-Type-Options", "xcto", x.lower() != "nosniff", x or "not offered", "nosniff (OK)")
    for name, key in (("Referrer-Policy", "referrer"), ("Permissions-Policy", "permissions")):
        v = hdrs.get(name.lower(), "")
        check(S, name, key, not v, "not offered", f"{v} (OK)")
    if "x-xss-protection" in hdrs:
        rows.append((S, "X-XSS-Protection", hdrs["x-xss-protection"] + " (deprecated, CSP preferred)", "INFO"))

    B, srv = "Banners", hdrs.get("server", "")
    check(B, "Server", "server-version", bool(re.search(r"\d", srv)), srv, f"{srv or '(empty / hidden)'} (OK)", [f"Server: {srv}"])
    tech = [f"{h}: {hdrs[h]}" for h in TECH_HEADERS if hdrs.get(h)]
    check(B, "Application banner", "tech-banner", bool(tech), "; ".join(tech), "none disclosed (OK)", tech)

    P = "Reverse proxy / X-Forwarded"
    prox = [f"{h}: {hdrs[h]}" for h in PROXY_HEADERS if hdrs.get(h)]
    check(P, "Proxy / cache headers", "proxy-banner", bool(prox), "; ".join(prox), "none disclosed (OK)", prox)
    priv = re.findall(r"\b(?:10|127|192\.168|172\.(?:1[6-9]|2\d|3[01]))(?:\.\d{1,3}){2,3}\b", " ".join(hdrs.values()))
    check(P, "Internal IP in headers", "internal-ip", bool(priv), ", ".join(sorted(set(priv))), "none (OK)", sorted(set(priv)))
    check(P, f"X-Forwarded-Host injection ({PROBE_HOST})", "xfh-reflect", reflected, f"REFLECTED in {reflected}",
          "not reflected (OK)", [f"reflected in {reflected}"] if reflected else [])

    C = "Cookies"
    if not cookies:
        rows.append((C, "Set-Cookie", "no cookies set", "INFO"))
    weak = []
    for c in cookies:
        name, attrs = c.split("=", 1)[0].strip(), c.lower()
        miss = [f for f, ok in (("Secure", "; secure" in attrs or not url.startswith("https")),
                                ("HttpOnly", "httponly" in attrs), ("SameSite", "samesite" in attrs)) if not ok]
        rows.append((C, name, f"missing {', '.join(miss)}" if miss else "Secure; HttpOnly; SameSite (OK)", "LOW" if miss else "OK"))
        if miss:
            weak.append(f"{name}: missing {', '.join(miss)}")
    if weak:
        add("cookie-flags", weak)

    O = "Other"
    acao = hdrs.get("access-control-allow-origin", "")
    check(O, "Access-Control-Allow-Origin", "cors", acao == "*", "* (any origin)", acao or "not set (OK)")
    check(O, "BREACH (HTTP compression)", "breach", bool(compressed), f"potentially VULNERABLE, uses {compressed}",
          "no HTTP compression (OK)", [f"Content-Encoding: {compressed}"] if compressed else [])
    return out, rows


def header_scan(targets, log):
    """One GET per target (no redirects followed, like testssl.sh). Returns (findings, {url: {"rows": [...]}})."""
    import gzip, ssl, urllib.error, urllib.request, zlib

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    # ponytail: certificate is not verified here; the TLS module reports trust problems
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
    found, tables = [], {}
    for t in dict.fromkeys(targets):
        url = t if "://" in t else "https://" + t
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (VA-Scanner)", "Accept-Encoding": "gzip, deflate",
                                                   "X-Forwarded-Host": PROBE_HOST})
        try:
            try:
                r = opener.open(req, timeout=15)
            except urllib.error.HTTPError as e:  # 3xx/4xx/5xx still carry the headers we check
                r = e
            body, status = r.read(500000), r.code
        except Exception as ex:
            log(f"[headers] {url}: {ex}\n")
            tables[url] = {"rows": [("Response", "HTTP request", f"failed: {ex}", "INFO")]}
            continue
        enc = (r.headers.get("Content-Encoding") or "").lower()
        try:
            body = gzip.decompress(body) if "gzip" in enc else zlib.decompress(body) if "deflate" in enc else body
        except Exception:
            pass
        hdrs = {k.lower(): v.strip() for k, v in r.headers.items()}
        where = [w for w, s in (("headers", " ".join(hdrs.values())), ("body", body.decode("latin-1"))) if PROBE_HOST in s]
        f, rows = header_findings(url, status, hdrs, r.headers.get_all("Set-Cookie") or [], " + ".join(where), enc)
        tables[url] = {"rows": rows}
        found += f
        log(f"[headers] {url}: HTTP {status}, {len(f)} issue(s)\n")
    return found, tables


def load_json(outdir, name):
    try:
        with open(os.path.join(outdir, name), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def load_tls(outdir):
    try:
        with open(os.path.join(outdir, "tls.json"), encoding="utf-8") as fh:
            t = json.load(fh)
    except (OSError, ValueError):
        return {}
    # earlier builds stored only the row list
    return {k: v if isinstance(v, dict) else {"grade": {"grade": "-", "caps": []}, "ciphers": [], "rows": v}
            for k, v in t.items()}


def sev_of(r):
    s = r.get("info", {}).get("severity", "info")
    return s if s in SEVS else "info"


def rank(s):  # critical first
    return -SEVS.index(s)


def load_findings(outdir):
    """findings.jsonl (current) or findings.json (older scans: JSON array). Skips a half-written last line."""
    for name in ("findings.jsonl", "findings.json"):
        path = os.path.join(outdir, name)
        if os.path.exists(path):
            text = open(path, encoding="utf-8", errors="replace").read().strip()
            if text.startswith("["):
                return json.loads(text)
            rows = []
            for line in text.splitlines():
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    pass
            return rows
    return []


def counts(rows):
    return {s: sum(sev_of(r) == s for r in rows) for s in reversed(SEVS)}


def group(rows, key):
    """[(key, [rows])] sorted by worst severity then size, the way scanners list vulns/hosts."""
    g = {}
    for r in rows:
        g.setdefault(key(r), []).append(r)
    return sorted(g.items(), key=lambda kv: (min(rank(sev_of(r)) for r in kv[1]), -len(kv[1]), kv[0]))


def read_meta(outdir):
    try:
        with open(os.path.join(outdir, "scan.json"), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {"name": os.path.basename(outdir), "status": "unknown"}


def write_meta(outdir, **kw):
    m = read_meta(outdir) if os.path.exists(os.path.join(outdir, "scan.json")) else {}
    m.update(kw)
    with open(os.path.join(outdir, "scan.json"), "w", encoding="utf-8") as fh:
        json.dump(m, fh, ensure_ascii=False, indent=1)


def make_html(outdir, targets, name="VA Scan"):
    e = html.escape
    rows = load_findings(outdir)
    cards = "".join(f'<div class="card" style="border-color:{SEV_COLOR[s]}"><b>{n}</b>{s}</div>'
                    for s, n in counts(rows).items())
    host_rows = "".join(f"<tr><td>{e(h)}</td>" + "".join(f"<td>{n or ''}</td>" for n in counts(rs).values()) + "</tr>"
                        for h, rs in group(rows, lambda r: r.get("host", "")))
    items = []
    for tid, rs in group(rows, lambda r: r.get("template-id", "")):
        r = rs[0]
        i = r.get("info", {})
        sev = sev_of(r)
        refs = i.get("reference") or []
        refs = [refs] if isinstance(refs, str) else refs
        extra = sorted({str(x) for x in rs for x in (x.get("extracted-results") or [])})
        detail = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in [
            ("Template", e(tid)),
            ("Affected", "<br>".join(sorted({e(x.get("matched-at", x.get("host", ""))) for x in rs}))),
            ("Description", e(i.get("description", "")).replace("\n", "<br>")),
            ("Remediation", e(i.get("remediation", "")).replace("\n", "<br>")),
            ("Extracted", "<br>".join(e(x) for x in extra)),
            ("References", "<br>".join(f'<a href="{e(u)}">{e(u)}</a>' for u in refs if str(u).startswith("http"))),
            ("Reproduce", f"<pre>{e(r.get('curl-command', ''))}</pre>" if r.get("curl-command") else ""),
        ] if v)
        items.append(f'<details><summary><span class="sev" style="background:{SEV_COLOR[sev]}">{e(sev)}</span>'
                     f'{e(i.get("name", tid))} <small>{len(rs)} instance(s)</small></summary><dl>{detail}</dl></details>')
    body = "".join(items) or "<p>No findings for the selected severities.</p>"
    hosts = (f"<h2>Hosts</h2><table><tr><th>Host</th>" + "".join(f"<th>{s}</th>" for s in reversed(SEVS)) +
             f"</tr>{host_rows}</table>") if host_rows else ""
    tls = ""
    badge = lambda st, txt: f'<span class="st" style="background:{STATUS_COLOR.get(st, "#999")}">{e(txt)}</span>'
    def check_table(rows):  # testssl-style table: section bars + check / result / status
        body_rows, last = [], None
        for sec, chk, result, st in rows:
            if sec != last:
                body_rows.append(f'<tr class="sec"><td colspan="3">{e(sec)}</td></tr>')
                last = sec
            body_rows.append(f'<tr><td>{e(str(chk))}</td><td style="color:{STATUS_COLOR.get(st, "#222")}">{e(str(result))}</td>'
                             f'<td>{badge(st, st)}</td></tr>')
        return f'<table class="tls"><tr><th>Check</th><th>Result</th><th>Status</th></tr>{"".join(body_rows)}</table>'

    ports = "".join(f'<tr><td>{e(h)}</td><td>{p["port"]}</td><td>{e(p["service"])}</td><td>{badge(p["severity"].upper(), p["severity"])}'
                    f'</td><td>{e(p["banner"])}</td><td>{e(p["note"])}</td></tr>'
                    for h, ps in load_json(outdir, "ports.json").items()
                    for p in sorted(ps, key=lambda p: (rank(p["severity"]), p["port"])))
    if ports:
        ports = (f'<h2>Open ports / พอร์ตที่เปิด</h2><table class="tls ciphers"><tr><th>Host</th><th>Port</th><th>Service</th>'
                 f'<th>Risk</th><th>Banner</th><th>Note</th></tr>{ports}</table>')
    hdrs = "".join(f"<h3>{e(u)}</h3>{check_table(t['rows'])}" for u, t in load_json(outdir, "headers.json").items())
    if hdrs:
        hdrs = f"<h2>HTTP headers (testssl-style)</h2>{hdrs}"
    for loc, t in load_tls(outdir).items():  # testssl-style table per endpoint
        cl = t["ciphers"]
        crows = "".join(f'<tr><td>{e(c["protocol"])}</td><td>{e(c["name"])}</td><td>{e(c["openssl"])}</td>'
                        f'<td>{e(c["kx"])}</td><td>{c["bits"]}</td><td>{badge(c["status"], c["strength"])}</td></tr>' for c in cl)
        g = t["grade"].get("grade", "-")
        tls += (f'<h3><span class="grade" style="background:{GRADE_COLOR.get(g, "#757575")}">{e(g)}</span>{e(loc)}</h3>'
                + check_table(t["rows"]) + (f'<h4>Accepted cipher suites / cipher ที่เซิร์ฟเวอร์ยอมรับ ({len(cl)})</h4><table class="tls ciphers">'
                   f'<tr><th>Protocol</th><th>IANA name</th><th>OpenSSL name</th><th>Key exchange</th><th>Bits</th>'
                   f'<th>Strength</th></tr>{crows}</table>' if cl else ""))
    if tls:
        tls = f"<h2>SSL/TLS (testssl-style)</h2>{tls}"
    page = f"""<!doctype html><html><head><meta charset="utf-8"><title>VA Scan Report</title><style>
body{{font-family:Segoe UI,Tahoma,sans-serif;max-width:1100px;margin:24px auto;padding:0 16px;color:#222}}
.cards{{display:flex;gap:10px;margin:16px 0}}.card{{border-left:6px solid;padding:8px 16px;background:#f5f5f5;min-width:90px}}
.card b{{display:block;font-size:26px}}details{{border:1px solid #ddd;border-radius:6px;margin:6px 0;padding:8px 12px}}
summary{{cursor:pointer;font-weight:600}}small{{color:#666;font-weight:400;margin-left:8px}}
.sev{{color:#fff;border-radius:4px;padding:2px 8px;margin-right:8px;font-size:12px;text-transform:uppercase}}
table{{border-collapse:collapse}}td,th{{border:1px solid #ddd;padding:4px 10px;text-align:center}}td:first-child{{text-align:left}}
dt{{font-weight:600;margin-top:8px}}dd{{margin:2px 0 0 0;word-break:break-all}}pre{{white-space:pre-wrap;background:#f5f5f5;padding:8px}}
table.tls{{width:100%;margin-bottom:16px}}table.tls td{{text-align:left;overflow-wrap:anywhere}}table.tls td:first-child{{width:230px;overflow-wrap:normal}}table.tls td:last-child{{width:90px;text-align:center}}
tr.sec td{{background:#263238;color:#fff;font-weight:600}}.st{{color:#fff;border-radius:4px;padding:1px 8px;font-size:12px;white-space:nowrap}}
table.ciphers td,table.ciphers td:first-child{{width:auto;white-space:nowrap;font-size:13px;overflow-wrap:normal}}.grade{{display:inline-block;color:#fff;font-size:30px;font-weight:700;min-width:60px;
text-align:center;border-radius:8px;padding:4px 10px;margin-right:12px;vertical-align:middle}}
@media print{{details{{break-inside:avoid}}tr{{break-inside:avoid}}}}</style></head><body>
<h1>Vulnerability Assessment Report</h1>
<p><b>{e(name)}</b> &middot; Scan time: {e(os.path.basename(outdir))} &middot; Findings: {len(rows)}</p>
<p>Targets: {"<br>".join(e(t) for t in targets)}</p>
<div class="cards">{cards}</div>{hosts}<h2>Vulnerabilities</h2>{body}{ports}{tls}{hdrs}</body></html>"""
    path = os.path.join(outdir, "report.html")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(page)
    return path


def detail_text(rs):
    r = rs[0]
    i = r.get("info", {})
    refs = i.get("reference") or []
    refs = [refs] if isinstance(refs, str) else refs
    parts = [("Severity / ความรุนแรง", f"{sev_of(r)} ({SEV_TH[sev_of(r)]})"),
             ("Template", r.get("template-id", "")),
             ("Affected / จุดที่พบ", "\n".join(sorted({x.get("matched-at", x.get("host", "")) for x in rs}))),
             ("Description / รายละเอียด", i.get("description", "")),
             ("Remediation / วิธีแก้ไข", i.get("remediation", "")),
             ("Extracted / ข้อมูลที่พบ", "\n".join(sorted({str(v) for x in rs for v in (x.get("extracted-results") or [])}))),
             ("References / อ้างอิง", "\n".join(map(str, refs))),
             ("Reproduce / ทดสอบซ้ำ", r.get("curl-command", ""))]
    return "\n\n".join([i.get("name", r.get("template-id", ""))] + [f"{k}\n{v}" for k, v in parts if v])


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("VA Scanner")
        self.geometry("1200x900")
        self.proc = None
        self.running_dir = None   # report folder of the scan in progress
        self.shown_dir = None     # report folder shown in Results
        self.host_filter = None
        self.rows = []
        try:  # Windows 11 look; falls back to plain ttk when sv-ttk is not installed
            import sv_ttk; sv_ttk.set_theme("light")
        except Exception:
            pass
        style = ttk.Style(self)
        style.configure("Treeview", rowheight=28)
        style.configure("TNotebook.Tab", padding=(14, 6))
        style.configure("Hint.TLabel", foreground="#6b7280")

        # status bar: what is running + elapsed time, with a busy indicator
        sbar = ttk.Frame(self, padding=(10, 4)); sbar.pack(side="bottom", fill="x")
        self.status = ttk.Label(sbar, text="Ready / พร้อมใช้งาน", style="Hint.TLabel"); self.status.pack(side="left")
        self.prog = ttk.Progressbar(sbar, mode="indeterminate", length=160)
        ttk.Label(sbar, text="Ctrl+N new · Ctrl+Enter launch · Ctrl+F search · F5 refresh",
                  style="Hint.TLabel").pack(side="right")
        self.tabs = ttk.Notebook(self); self.tabs.pack(fill="both", expand=True, padx=8, pady=(8, 0))
        self.build_scans_tab()
        self.build_new_tab()
        self.build_results_tab()
        self.refresh_scans()
        self.after(300, self.first_run)
        self.after(3000, self.tick)
        self.bind_all("<Control-n>", lambda e: (self.tabs.select(1), self.targets.focus_set()))
        self.bind_all("<Control-Return>", lambda e: self.run() if self.tabs.index("current") == 1 else None)
        self.bind_all("<Control-f>", lambda e: (self.tabs.select(2), self.sub.select(0), self.search.focus_set()))
        self.bind_all("<F5>", lambda e: (self.refresh_scans(), self.shown_dir and self.show_results(self.shown_dir)))

    @staticmethod
    def scroll(tv):
        """Vertical scrollbar for a Treeview that sits alone in its own frame."""
        sb = ttk.Scrollbar(tv.master, orient="vertical", command=tv.yview); tv.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y"); tv.pack(side="left", fill="both", expand=True)
        return tv

    # ---------- My Scans ----------
    def build_scans_tab(self):
        t = ttk.Frame(self.tabs, padding=8); self.tabs.add(t, text="  My Scans / สแกนของฉัน  ")
        bar = ttk.Frame(t); bar.pack(fill="x", pady=(0, 6))
        ttk.Button(bar, text="+ New Scan / สร้างสแกนใหม่", style="Accent.TButton",
                   command=lambda: self.tabs.select(1)).pack(side="left")
        ttk.Button(bar, text="View results / ดูผล", command=self.open_selected).pack(side="left", padx=4)
        ttk.Button(bar, text="HTML report / รายงาน", command=self.open_html).pack(side="left", padx=4)
        ttk.Button(bar, text="Re-run / สแกนซ้ำ", command=self.rerun).pack(side="left", padx=4)
        ttk.Button(bar, text="Open folder / เปิดโฟลเดอร์", command=lambda: (os.makedirs(REPORTS, exist_ok=True),
                                                                          os.startfile(REPORTS))).pack(side="left", padx=4)
        ttk.Button(bar, text="Update templates / อัปเดตเทมเพลต", command=self.update_templates).pack(side="right")
        cols = ("name", "template", "targets", "date", "status") + tuple(reversed(SEVS))
        self.scans = ttk.Treeview(ttk.Frame(t), columns=cols, show="headings", selectmode="browse")
        heads = {"name": "Name / ชื่อ", "template": "Template / รูปแบบ", "targets": "Targets / เป้าหมาย",
                 "date": "Date / วันที่", "status": "Status / สถานะ"}
        widths = {"name": 210, "template": 180, "targets": 230, "date": 120, "status": 90}
        for c in cols:
            self.scans.heading(c, text=heads.get(c, c.title()))
            self.scans.column(c, width=widths.get(c, 62), anchor="w" if c in widths else "center")
        ttk.Label(t, text="ดับเบิลคลิกเพื่อดูผล / Double-click a scan to open its results",
                  style="Hint.TLabel").pack(side="bottom", anchor="w", pady=(4, 0))
        self.scans.master.pack(fill="both", expand=True); self.scroll(self.scans)
        self.scans.bind("<Double-1>", lambda e: self.open_selected())
        self.scans.tag_configure("running", foreground="#1976d2")
        self.scans.tag_configure("failed", foreground="#d32f2f")

    def refresh_scans(self):
        sel = self.scans.selection()
        self.scans.delete(*self.scans.get_children())
        if not os.path.isdir(REPORTS):
            return
        for d in sorted(os.listdir(REPORTS), reverse=True):
            path = os.path.join(REPORTS, d)
            if not os.path.isdir(path):
                continue
            m = read_meta(path)
            c = counts(load_findings(path))
            status = m.get("status", "unknown")
            targets = m.get("targets") or self.targets_file(path)
            self.scans.insert("", "end", iid=path, tags=(status,), values=(
                m.get("name", d), m.get("preset", ""), f"{len(targets)}: {', '.join(targets)[:60]}",
                time.strftime("%Y-%m-%d %H:%M", time.strptime(d[:15], "%Y%m%d-%H%M%S")) if d[:8].isdigit() else d,
                status, *[c[s] or "" for s in reversed(SEVS)]))
        if sel and self.scans.exists(sel[0]):
            self.scans.selection_set(sel[0])

    @staticmethod
    def targets_file(path):  # scans made before scan.json existed
        try:
            return open(os.path.join(path, "targets.txt"), encoding="utf-8").read().split()
        except OSError:
            return []

    def selected_dir(self):
        sel = self.scans.selection()
        if not sel:
            messagebox.showinfo("VA Scanner", "เลือกสแกนในรายการก่อน / Select a scan first.")
        return sel[0] if sel else None

    def open_selected(self):
        d = self.selected_dir()
        if d:
            self.show_results(d); self.tabs.select(2)

    def open_html(self):
        d = self.selected_dir()
        if d:
            m = read_meta(d)
            os.startfile(make_html(d, m.get("targets", []), m.get("name", "")))

    def rerun(self):
        d = self.selected_dir()
        if not d:
            return
        m = read_meta(d)
        self.name.delete(0, "end"); self.name.insert(0, m.get("name", "") + " (re-run)")
        self.targets.delete("1.0", "end"); self.targets.insert("1.0", "\n".join(m.get("targets", [])))
        if m.get("preset") in PRESETS:
            self.preset.set(m["preset"])
        for c, v in self.cat_vars.items(): v.set(c in m.get("cats", []))
        for s, v in self.sev_vars.items(): v.set(s in m.get("sevs", []))
        self.use_nuclei.set(m.get("nuclei", bool(m.get("cats"))))
        for k, v in self.mod_vars.items(): v.set(bool(m.get(k)))
        self.port_spec.delete(0, "end"); self.port_spec.insert(0, m.get("ports") or "top")
        self.tags.delete(0, "end"); self.tags.insert(0, m.get("tags", ""))
        self.auth.set(False)  # authorization must be re-confirmed for every run
        self.tabs.select(1)

    # ---------- New Scan ----------
    def build_new_tab(self):
        t = ttk.Frame(self.tabs, padding=12); self.tabs.add(t, text="  New Scan / สร้างสแกนใหม่  ")
        ttk.Label(t, text="①  Targets / ใส่เป้าหมาย", font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 4))
        f = ttk.Frame(t); f.pack(fill="x")
        ttk.Label(f, text="Scan name / ชื่องานสแกน").grid(row=0, column=0, sticky="w")
        self.name = ttk.Entry(f, width=50); self.name.grid(row=0, column=1, sticky="w", pady=2)
        ttk.Label(f, text="Targets / เป้าหมาย\n(1 บรรทัดต่อ 1 URL หรือ IP)").grid(row=1, column=0, sticky="nw")
        self.targets = tk.Text(f, width=80, height=5); self.targets.grid(row=1, column=1, sticky="we", pady=2)

        ttk.Label(t, text="②  Choose what to check / เลือกรูปแบบการสแกน  (เลือกอย่างเดียวพอ — ระบบตั้งค่าที่เหลือให้)",
                  font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(12, 4))
        cards = ttk.Frame(t); cards.pack(fill="x")
        self.preset = tk.StringVar(value=DEFAULT_PRESET)
        for i, (p, (_, _, _, desc, _)) in enumerate(PRESETS.items()):
            danger = desc.startswith("INTRUSIVE")
            text = ("⚠ " if danger else "") + p + "\n" + textwrap.fill(desc, 42, max_lines=2, placeholder="…")
            ttk.Radiobutton(cards, text=text, variable=self.preset, value=p, command=self.apply_preset,
                            style="Toggle.TButton").grid(row=i // 4, column=i % 4, padx=4, pady=4, sticky="nsew")
        for c in range(4):
            cards.columnconfigure(c, weight=1, uniform="card")
        info = ttk.LabelFrame(t, text="What this scan does / สิ่งที่จะตรวจ", padding=(10, 6))
        info.pack(fill="x", pady=(6, 0))
        self.preset_info = ttk.Label(info, justify="left", wraplength=1100)
        self.preset_info.pack(anchor="w", fill="x")
        info.bind("<Configure>", lambda e: self.preset_info.config(wraplength=max(e.width - 30, 300)))

        ttk.Button(t, text="⚙  Customize… / ปรับแต่งเอง  (ไม่จำเป็น — ไม่ต้องแตะก็สแกนได้)",
                   command=self.show_adv).pack(anchor="w", pady=(8, 0))
        # Customize lives in its own window so the New Scan screen always fits
        self.adv_win = tk.Toplevel(self); self.adv_win.withdraw(); self.adv_win.transient(self)
        self.adv_win.title("Customize / ปรับแต่ง"); self.adv_win.protocol("WM_DELETE_WINDOW", self.adv_win.withdraw)
        ttk.Button(self.adv_win, text="Done / เสร็จ", style="Accent.TButton",
                   command=self.adv_win.withdraw).pack(side="bottom", anchor="e", padx=10, pady=(0, 10))
        self.adv = ttk.LabelFrame(self.adv_win, text="Customize / ปรับแต่ง  ·  ค่าทั้งหมดถูกตั้งตามรูปแบบที่เลือกในข้อ ② แล้ว "
                                          "แก้เฉพาะเมื่อต้องการ", padding=8)
        a = self.adv; a.pack(fill="both", expand=True, padx=10, pady=10)
        ttk.Label(a, text="Templates / ชุดการตรวจ").grid(row=0, column=0, sticky="nw")
        self.cat_vars = {c: tk.BooleanVar() for c in CATS}
        for i, c in enumerate(CATS):
            ttk.Checkbutton(a, text=f"{c} ({TH[c]})", variable=self.cat_vars[c]).grid(
                row=i // 4, column=1 + i % 4, sticky="w")
        r = (len(CATS) + 3) // 4
        ttk.Label(a, text="Severity / ความรุนแรง").grid(row=r, column=0, sticky="w")
        self.sev_vars = {s: tk.BooleanVar() for s in SEVS}
        sf = ttk.Frame(a); sf.grid(row=r, column=1, columnspan=4, sticky="w")
        for s in SEVS:
            ttk.Checkbutton(sf, text=f"{s} ({SEV_TH[s]})", variable=self.sev_vars[s]).pack(side="left")
        ttk.Label(a, text="Extra tags / แท็ก").grid(row=r + 1, column=0, sticky="w")
        self.tags = ttk.Entry(a, width=30); self.tags.grid(row=r + 1, column=1, sticky="w")
        ttk.Label(a, text="Rate / ความเร็ว (ครั้ง/วินาที)").grid(row=r + 1, column=2, sticky="e")
        self.rate = ttk.Spinbox(a, from_=1, to=150, width=6); self.rate.set(20); self.rate.grid(row=r + 1, column=3, sticky="w")

        mf = ttk.LabelFrame(a, text="Scanners to run / เครื่องมือที่จะรัน", padding=6)
        mf.grid(row=r + 2, column=0, columnspan=5, sticky="we", pady=(8, 0))
        self.use_nuclei = tk.BooleanVar()
        ttk.Checkbutton(mf, variable=self.use_nuclei, text="nuclei / ใช้ชุดตรวจที่ติ๊กไว้ด้านบน").grid(
            row=0, column=0, columnspan=3, sticky="w")
        self.mod_vars = {k: tk.BooleanVar() for k in MODULES}
        texts = {"ports": "Port scan / สแกนพอร์ต TCP + banner  ·  พอร์ต:",
                 "tls": "SSL/TLS deep check (testssl-style): โปรโตคอล cipher ใบรับรอง Heartbleed ROBOT SWEET32 BEAST LUCKY13 RC4 ...",
                 "headers": "HTTP headers (testssl -h): security headers, Server/X-Powered-By, X-Forwarded-*, cookie, CORS, BREACH"}
        for i, k in enumerate(MODULES, 1):
            ttk.Checkbutton(mf, variable=self.mod_vars[k], text=texts[k]).grid(row=i, column=0, sticky="w")
        self.port_spec = ttk.Entry(mf, width=28); self.port_spec.insert(0, "top"); self.port_spec.grid(row=1, column=1, sticky="w")
        ttk.Label(mf, text="top / all / 1-1024,3389", foreground="#666").grid(row=1, column=2, sticky="w", padx=6)
        self.bottom = ttk.Frame(t); self.bottom.pack(fill="x", pady=(10, 0))
        ttk.Label(self.bottom, text="③  Confirm & launch / ยืนยันและเริ่มสแกน", font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 4))
        self.auth = tk.BooleanVar()
        ttk.Checkbutton(self.bottom, text="I have written authorization / ได้รับอนุญาตเป็นลายลักษณ์อักษรให้ทดสอบเป้าหมายนี้แล้ว",
                        variable=self.auth).pack(anchor="w")
        self.run_btn = ttk.Button(self.bottom, text="▶  Launch scan / เริ่มสแกน  (Ctrl+Enter)", style="Accent.TButton",
                                  command=self.run)
        self.run_btn.pack(anchor="w", pady=6, ipadx=10, ipady=4)
        self.apply_preset()

    def show_adv(self):
        self.adv_win.deiconify(); self.adv_win.lift(); self.adv_win.focus_set()

    def apply_preset(self):
        cats, sevs, tags, _, mods = PRESETS[self.preset.get()]
        self.preset_info.config(text=preset_details(self.preset.get()))
        self.use_nuclei.set(bool(cats))
        for k, v in self.mod_vars.items(): v.set(k in mods)
        self.tags.delete(0, "end"); self.tags.insert(0, tags)
        for c, v in self.cat_vars.items(): v.set(c in cats)
        for s, v in self.sev_vars.items(): v.set(s in sevs)

    def run(self):
        targets = [t.strip() for t in self.targets.get("1.0", "end").splitlines() if t.strip()]
        cats = [c for c, v in self.cat_vars.items() if v.get()] if self.use_nuclei.get() else []
        sevs = [s for s, v in self.sev_vars.items() if v.get()]
        mods = {k: v.get() for k, v in self.mod_vars.items()}
        if not targets or not (cats or any(mods.values())):
            return messagebox.showwarning("VA Scanner", "กรุณาใส่เป้าหมายอย่างน้อย 1 รายการ และเลือก nuclei template หรือโมดูลอย่างน้อย 1 อย่าง\n"
                                                        "Enter at least one target and pick nuclei templates or a module.")
        if mods["ports"]:
            try:
                parse_ports(self.port_spec.get())
            except ValueError as ex:
                return messagebox.showwarning("VA Scanner", f"รูปแบบพอร์ตไม่ถูกต้อง / Bad port list: {ex}")
        if not self.auth.get():  # trust boundary: no scan without confirmed authorization
            return messagebox.showwarning("VA Scanner", "กรุณายืนยันว่าได้รับอนุญาตให้ทดสอบเป้าหมายนี้แล้ว\n"
                                                        "Confirm you are authorized to test these targets.")
        if any("intrusive" in c for c in cats) and not messagebox.askyesno(
                "VA Scanner", "เลือกชุดตรวจแบบ intrusive ซึ่งอาจกระทบระบบเป้าหมาย\nหัวหน้าอนุมัติการสแกนนี้แล้วใช่ไหม?\n\n"
                              "Intrusive templates selected. Senior approved this scan?"):
            return
        if self.busy():
            return
        stamp = time.strftime("%Y%m%d-%H%M%S")
        outdir = os.path.join(REPORTS, stamp)
        os.makedirs(outdir)
        tfile = os.path.join(outdir, "targets.txt")
        with open(tfile, "w", encoding="utf-8") as fh:
            fh.write("\n".join(targets))
        name = self.name.get().strip() or f"Scan {stamp}"
        write_meta(outdir, name=name, preset=self.preset.get(), targets=targets, cats=cats, sevs=sevs,
                   tags=self.tags.get().strip(), rate=self.rate.get(), nuclei=bool(cats), tls=mods["tls"],
                   headers=mods["headers"], ports=self.port_spec.get().strip() if mods["ports"] else "", status="running")
        self.name.delete(0, "end"); self.auth.set(False)
        cmd = build_cmd(tfile, cats, sevs, self.tags.get().strip(), self.rate.get(), outdir) if cats else None
        self.running_dir = outdir
        self.refresh_scans()
        self.show_results(outdir); self.tabs.select(2)
        self.start(cmd, outdir)

    # ---------- Results ----------
    def build_results_tab(self):
        t = ttk.Frame(self.tabs, padding=8); self.tabs.add(t, text="  Results / ผลการสแกน  ")
        head = ttk.Frame(t); head.pack(fill="x")
        self.res_title = ttk.Label(head, text="เลือกสแกนจาก My Scans / Pick a scan in My Scans",
                                   font=("Segoe UI", 12, "bold")); self.res_title.pack(side="left")
        ttk.Button(head, text="HTML report / รายงาน", command=self.results_html).pack(side="right")
        self.stop_btn = ttk.Button(head, text="■ Stop / หยุด", command=self.stop); self.stop_btn.pack(side="right", padx=4)
        chips = ttk.Frame(t); chips.pack(fill="x", pady=6)
        self.chip = {}
        for s in reversed(SEVS):
            self.chip[s] = tk.Label(chips, text="", bg=SEV_COLOR[s], fg="white", width=14, height=2,
                                    font=("Segoe UI", 10, "bold"))
            self.chip[s].pack(side="left", padx=3)
        # sv-ttk runs tk_setPalette on every <<ThemeChanged>>, which repaints all tk widgets; put the chip colours back
        self.bind_all("<<ThemeChanged>>", lambda e: e.widget is self and self.after_idle(
            lambda: [c.config(bg=SEV_COLOR[s], fg="white") for s, c in self.chip.items()]), add="+")
        self.filter_lbl = ttk.Label(chips, text=""); self.filter_lbl.pack(side="left", padx=10)
        self.search_var = tk.StringVar()
        self.search = ttk.Entry(chips, textvariable=self.search_var, width=28); self.search.pack(side="right")
        ttk.Label(chips, text="🔍 Search / ค้นหา").pack(side="right", padx=4)
        self.search_var.trace_add("write", lambda *_: self.shown_dir and self.show_results(self.shown_dir))

        self.sub = ttk.Notebook(t); self.sub.pack(fill="both", expand=True)
        # Vulnerabilities: grouped list + detail pane
        pv = ttk.PanedWindow(self.sub, orient="horizontal"); self.sub.add(pv, text=" Vulnerabilities / ช่องโหว่ ")
        self.vulns = ttk.Treeview(ttk.Frame(pv), columns=("sev", "name", "count"), show="tree headings", selectmode="browse")
        for c, txt, w in (("sev", "Severity", 90), ("name", "Name / ชื่อช่องโหว่", 420), ("count", "Count", 60)):
            self.vulns.heading(c, text=txt); self.vulns.column(c, width=w, anchor="w" if c == "name" else "center")
        self.vulns.column("#0", width=24, stretch=False)
        for s in SEVS:
            self.vulns.tag_configure(s, foreground=SEV_COLOR[s])
        self.vulns.bind("<<TreeviewSelect>>", self.show_detail)
        self.detail = scrolledtext.ScrolledText(pv, wrap="word", font=("Segoe UI", 10))
        pv.add(self.vulns.master, weight=3); pv.add(self.detail, weight=2); self.scroll(self.vulns)
        # Hosts: per-host severity counts, double-click to drill into that host's vulns
        hf = ttk.Frame(self.sub); self.sub.add(hf, text=" Hosts / เครื่องเป้าหมาย ")
        self.hosts = ttk.Treeview(hf, columns=("host",) + tuple(reversed(SEVS)), show="headings")
        self.hosts.heading("host", text="Host"); self.hosts.column("host", width=400)
        for s in reversed(SEVS):
            self.hosts.heading(s, text=s.title()); self.hosts.column(s, width=80, anchor="center")
        self.hosts.bind("<Double-1>", self.drill_host)
        ttk.Label(hf, text="ดับเบิลคลิกที่ host เพื่อดูช่องโหว่ของเครื่องนั้น / Double-click a host to see its vulnerabilities",
                  style="Hint.TLabel").pack(side="bottom", anchor="w")
        self.scroll(self.hosts)
        # Ports: one row per open port, risky services coloured by severity
        pf = ttk.Frame(self.sub); self.sub.add(pf, text=" Ports / พอร์ต ")
        cols = (("host", "Host", 170), ("port", "Port", 60), ("service", "Service", 110), ("risk", "Risk / ความเสี่ยง", 90),
                ("banner", "Banner", 330), ("note", "Note / หมายเหตุ", 360))
        self.portv = ttk.Treeview(pf, columns=[c[0] for c in cols], show="headings")
        for cid, txt, w in cols:
            self.portv.heading(cid, text=txt); self.portv.column(cid, width=w, anchor="center" if cid in ("port", "risk") else "w")
        for s in SEVS:
            self.portv.tag_configure(s, foreground=SEV_COLOR[s])
        self.port_lbl = ttk.Label(pf, text=""); self.port_lbl.pack(side="top", anchor="w")
        self.scroll(self.portv)
        # SSL/TLS: testssl-style table, host -> section -> check rows
        self.tlsv = self.check_tree(" SSL/TLS ")
        # Ciphers: every accepted cipher suite, sortable (like testssl -E)
        cf = ttk.Frame(self.sub); self.sub.add(cf, text=" Ciphers ")
        cols = (("host", "Host", 140), ("proto", "Protocol", 70), ("iana", "IANA name", 330), ("openssl", "OpenSSL name", 230),
                ("kx", "Key exch.", 100), ("bits", "Bits", 55), ("strength", "Strength / ความแข็งแรง", 210))
        self.ciph = ttk.Treeview(cf, columns=[c[0] for c in cols], show="headings")
        for cid, txt, w in cols:
            self.ciph.heading(cid, text=txt, command=lambda c=cid: self.sort_ciphers(c))
            self.ciph.column(cid, width=w, anchor="center" if cid in ("bits", "proto") else "w")
        for st, c in STATUS_COLOR.items():
            self.ciph.tag_configure(st, foreground=c)
        sb = ttk.Scrollbar(cf, orient="vertical", command=self.ciph.yview); self.ciph.configure(yscrollcommand=sb.set)
        self.ciph_lbl = ttk.Label(cf, text=""); self.ciph_lbl.pack(anchor="w")
        sb.pack(side="right", fill="y"); self.ciph.pack(fill="both", expand=True)
        self.hdrv = self.check_tree(" HTTP Headers ")
        # Raw log
        self.log = scrolledtext.ScrolledText(self.sub, font=("Consolas", 9)); self.sub.add(self.log, text=" Log ")

    def show_results(self, outdir):
        if outdir != self.shown_dir:
            self.host_filter = None
            self.log.delete("1.0", "end")
            if outdir != self.running_dir and os.path.exists(os.path.join(outdir, "scan.log")):
                self.log.insert("end", open(os.path.join(outdir, "scan.log"), encoding="utf-8", errors="replace").read())
        # module tables only change when their file is (re)written, so rebuild on mtime, not every tick
        stamp = tuple(os.path.getmtime(p) if os.path.exists(p) else 0
                      for p in (os.path.join(outdir, n) for n in ("tls.json", "ports.json", "headers.json")))
        if outdir != self.shown_dir or stamp != getattr(self, "_stamp", None):
            self._stamp = stamp
            tables = load_tls(outdir)
            self.ciph.delete(*self.ciph.get_children())
            self.fill_check_tree(self.tlsv, {
                loc: (f"{loc}    Grade {t['grade'].get('grade', '-')}",
                      f"Grade / เกรด: {t['grade'].get('grade', '-')}" + (
                          f"  (ถ้าใบรับรองน่าเชื่อถือ = {t['grade']['grade_ignoring_trust']})" if t["grade"].get("grade") == "T" else ""),
                      GRADE_STATUS.get(t["grade"].get("grade", "-"), "INFO"), t["rows"]) for loc, t in tables.items()})
            self.fill_check_tree(self.hdrv, {u: (u, "", "INFO", t["rows"]) for u, t in load_json(outdir, "headers.json").items()})
            self.portv.delete(*self.portv.get_children())
            ports = load_json(outdir, "ports.json")
            for h, ps in ports.items():
                for p in sorted(ps, key=lambda p: (rank(p["severity"]), p["port"])):
                    self.portv.insert("", "end", tags=(p["severity"],), values=(
                        h, p["port"], p["service"], p["severity"].upper(), p["banner"], p["note"]))
            n = len(self.portv.get_children())
            self.port_lbl.config(text=f"{n} open port(s) on {len(ports)} host(s) / พอร์ตที่เปิด" if ports else
                                 "Port scan not run for this scan / สแกนนี้ไม่ได้เลือกโมดูลสแกนพอร์ต")
            for loc, t in tables.items():
                for c in t["ciphers"]:
                    self.ciph.insert("", "end", tags=(c["status"],), values=(
                        loc, c["protocol"], c["name"], c["openssl"], c["kx"], c["bits"], c["strength"]))
            self.ciph_lbl.config(text=f"{len(self.ciph.get_children())} cipher suite(s) accepted / cipher ที่เซิร์ฟเวอร์ยอมรับ"
                                      "  ·  คลิกหัวคอลัมน์เพื่อเรียง / click a header to sort")
        self.shown_dir = outdir
        m = read_meta(outdir)
        self.res_title.config(text=f"{m.get('name', '')}   [{m.get('status', '')}]")
        self.rows = load_findings(outdir)
        c = counts(self.rows)
        for s in SEVS:
            self.chip[s].config(text=f"{c[s]}\n{s.upper()} / {SEV_TH[s]}")
        rows = [r for r in self.rows if r.get("host") == self.host_filter] if self.host_filter else self.rows
        q = self.search_var.get().strip().lower()
        if q:  # match name, template id, host or URL
            rows = [r for r in rows if q in " ".join((r.get("info", {}).get("name", ""), r.get("template-id", ""),
                                                      r.get("host", ""), r.get("matched-at", ""))).lower()]
        self.filter_lbl.config(text=f"Filter host: {self.host_filter}   (ดับเบิลคลิก host อื่น หรือเลือกสแกนใหม่เพื่อล้าง)"
                               if self.host_filter else "")
        sel = self.vulns.selection()
        open_ = {i for i in self.vulns.get_children() if self.vulns.item(i, "open")}
        self.vulns.delete(*self.vulns.get_children())
        self.groups = {}
        for tid, rs in group(rows, lambda r: r.get("template-id", "")):
            s = sev_of(rs[0])
            self.groups[tid] = rs
            self.vulns.insert("", "end", iid=tid, open=tid in open_, tags=(s,),
                              values=(s.upper(), rs[0].get("info", {}).get("name", tid), len(rs)))
            for n, r in enumerate(rs):
                self.vulns.insert(tid, "end", iid=f"{tid}\x00{n}", tags=(s,),
                                  values=("", r.get("matched-at", r.get("host", "")), ""))
        if sel and self.vulns.exists(sel[0]):
            self.vulns.selection_set(sel[0])
        elif self.vulns.get_children():
            self.vulns.selection_set(self.vulns.get_children()[0])
        self.hosts.delete(*self.hosts.get_children())
        for h, rs in group(self.rows, lambda r: r.get("host", "")):
            hc = counts(rs)
            self.hosts.insert("", "end", iid=h or "-", values=(h, *[hc[s] or "" for s in reversed(SEVS)]))

    def check_tree(self, title):
        """testssl-style tree: endpoint -> section -> (check, result, status). Used by SSL/TLS and HTTP Headers."""
        tv = ttk.Treeview(ttk.Frame(self.sub), columns=("result", "status"), show="tree headings")
        tv.heading("#0", text="Check / รายการตรวจ"); tv.column("#0", width=330)
        tv.heading("result", text="Result / ผล"); tv.column("result", width=660)
        tv.heading("status", text="Status"); tv.column("status", width=90, anchor="center")
        for st, c in STATUS_COLOR.items():
            tv.tag_configure(st, foreground=c)
        tv.tag_configure("sec", background="#e3e8ec", font=("Segoe UI", 9, "bold"))
        self.sub.add(tv.master, text=title)
        return self.scroll(tv)

    @staticmethod
    def fill_check_tree(tv, tables):
        """tables: {key: (label, result, status, rows)}"""
        tv.delete(*tv.get_children())
        for label, result, status, rows in tables.values():
            h = tv.insert("", "end", text=label, open=True, values=(result, status), tags=(status, "sec"))
            secs = {}
            for sec, chk, res, st in rows:
                if sec not in secs:
                    secs[sec] = tv.insert(h, "end", text=sec, open=True, tags=("sec",))
                tv.insert(secs[sec], "end", text=chk, values=(res, st), tags=(st,))

    def sort_ciphers(self, col):
        rows = [(self.ciph.set(i, col), i) for i in self.ciph.get_children()]
        rev = getattr(self, "_csort", None) == col
        rows.sort(key=lambda r: (int(r[0]) if r[0].isdigit() else r[0]), reverse=rev)
        for n, (_, i) in enumerate(rows):
            self.ciph.move(i, "", n)
        self._csort = None if rev else col

    def show_detail(self, _=None):
        sel = self.vulns.selection()
        if not sel:
            return
        tid, _, n = sel[0].partition("\x00")
        rs = self.groups.get(tid, [])
        rs = [rs[int(n)]] if n else rs
        self.detail.delete("1.0", "end")
        if rs:
            self.detail.insert("end", detail_text(rs))

    def drill_host(self, _=None):
        sel = self.hosts.selection()
        if sel:
            self.host_filter = self.hosts.item(sel[0], "values")[0]
            self.show_results(self.shown_dir); self.sub.select(0)

    def results_html(self):
        if self.shown_dir:
            m = read_meta(self.shown_dir)
            os.startfile(make_html(self.shown_dir, m.get("targets", []), m.get("name", "")))

    # ---------- process ----------
    def busy(self):
        if self.running_dir or (self.proc and self.proc.poll() is None):  # running_dir covers the TLS phase
            messagebox.showwarning("VA Scanner", "มีงานกำลังทำงานอยู่ รอให้เสร็จหรือกดหยุดก่อน\nA job is already running.")
            return True
        return False

    def update_templates(self):
        if self.busy():
            return
        self.shown_dir = None
        self.res_title.config(text="Updating templates / กำลังอัปเดตเทมเพลต")
        self.log.delete("1.0", "end"); self.tabs.select(2); self.sub.select(self.log)
        self.start([NUCLEI, "-nc", "-ut", "-ud", TPL], None)

    def start(self, cmd, outdir):
        self.log.insert("end", " ".join(cmd) + "\n\n" if cmd else "[nuclei] skipped (no templates selected)\n")
        self.run_btn.state(["disabled"])
        self.started = time.time()
        self.prog.pack(side="left", padx=10); self.prog.start(12)
        threading.Thread(target=self._worker, args=(cmd, outdir), daemon=True).start()

    def _worker(self, cmd, outdir):
        logf = open(os.path.join(outdir, "scan.log"), "w", encoding="utf-8") if outdir else None
        self.stopped, self.proc, code = False, None, 0
        def log(line):
            if logf:
                logf.write(line); logf.flush()
            self.after(0, self.log_line, line, outdir)
        if cmd:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                         encoding="utf-8", errors="replace", creationflags=subprocess.CREATE_NO_WINDOW)
            for line in self.proc.stdout:
                log(line)
            code = self.proc.wait()
        m = read_meta(outdir) if outdir else {}
        t = m.get("targets", [])
        modules = (("ports", "ports.json", lambda: port_scan(t, m["ports"], log, lambda: self.stopped)),
                   ("tls", "tls.json", lambda: tls_scan(t, log)),
                   ("headers", "headers.json", lambda: header_scan(t, log)))
        for key, fname, fn in modules:
            if not m.get(key) or self.stopped:
                continue
            log(f"\n[{key}] {MODULES[key]} ...\n")
            try:
                found, tables = fn()
                if key == "tls" and m.get("headers"):  # the headers module reports HSTS itself
                    found = [f for f in found if f["template-id"] != "tls-no-hsts"]
                found = [f for f in found if sev_of(f) in m.get("sevs", SEVS)]
                with open(os.path.join(outdir, fname), "w", encoding="utf-8") as fh:
                    json.dump(tables, fh, ensure_ascii=False, indent=1)
                with open(os.path.join(outdir, "findings.jsonl"), "a", encoding="utf-8") as fh:
                    fh.writelines(json.dumps(f, ensure_ascii=False) + "\n" for f in found)
            except Exception as ex:  # one module failing must never lose the results already on disk
                log(f"[{key}] error: {ex!r}\n")
        if logf:
            logf.close()
        self.after(0, self.finished, outdir, code)

    def log_line(self, line, outdir):
        if outdir == self.shown_dir:
            self.log.insert("end", line); self.log.see("end")

    def finished(self, outdir, code):
        self.run_btn.state(["!disabled"])
        self.prog.stop(); self.prog.pack_forget()
        self.status.config(text=f"Last job finished {time.strftime('%H:%M')} / งานล่าสุดเสร็จแล้ว")
        self.running_dir = None
        if not outdir:
            self.log.insert("end", f"\n[done, exit {code}]\n")
            return
        status = "stopped" if self.stopped else ("completed" if code == 0 else "failed")
        write_meta(outdir, status=status, exit_code=code, finished=time.strftime("%Y-%m-%d %H:%M:%S"))
        m = read_meta(outdir)
        try:
            make_html(outdir, m.get("targets", []), m.get("name", ""))
        except Exception as ex:  # a report bug must not hide the finished scan; results stay viewable in the app
            self.log.insert("end", f"\n[report error] {ex!r}\n")
        self.refresh_scans()
        if outdir == self.shown_dir:
            self.show_results(outdir)
        n = len(load_findings(outdir))
        messagebox.showinfo("VA Scanner", f"สแกน '{m.get('name')}' {status}\nพบ {n} รายการ / {n} findings")

    def tick(self):  # live refresh while a scan runs
        if self.running_dir or (self.proc and self.proc.poll() is None):
            m, s = divmod(int(time.time() - self.started), 60)
            what = read_meta(self.running_dir).get("name", "") if self.running_dir else "Updating templates"
            self.status.config(text=f"Running / กำลังทำงาน: {what}  ·  {m:02d}:{s:02d}  ·  {len(self.rows)} findings")
        if self.running_dir:
            self.refresh_scans()
            if self.shown_dir == self.running_dir:
                self.show_results(self.running_dir)
        self.after(3000, self.tick)

    def stop(self):
        if self.running_dir or (self.proc and self.proc.poll() is None):
            self.stopped = True  # skips the remaining modules; the port scan checks it per probe
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()

    def first_run(self):
        if not os.path.exists(NUCLEI):
            self.run_btn.state(["disabled"])
            return messagebox.showerror("VA Scanner", f"ไม่พบ nuclei.exe ใน {BASE}\nวาง nuclei.exe ไว้โฟลเดอร์เดียวกับโปรแกรม\n\n"
                                                      f"nuclei.exe not found in {BASE}")
        if not os.path.isdir(TPL):
            messagebox.showinfo("VA Scanner", "ครั้งแรก: จะดาวน์โหลด templates (ใช้อินเทอร์เน็ต ประมาณ 1-3 นาที)\n"
                                              "First run: downloading templates...")
            self.update_templates()


if __name__ == "__main__":
    if "--tls" in sys.argv:  # CLI: VA-Scanner.exe --tls <target> <out.json>  (works in the windowed exe too)
        _, t, out = sys.argv[sys.argv.index("--tls"):][:3]
        with open(out, "w", encoding="utf-8") as fh:
            found, tables = tls_scan([t], lambda s: None)
            json.dump({"findings": found, "tables": tables}, fh, ensure_ascii=False, indent=1)
        sys.exit()
    if "--test" in sys.argv:
        import tempfile
        c = build_cmd("t.txt", ["ssl"], ["high"], "arcgis", 10, "")
        assert c[:3] == [NUCLEI, "-l", "t.txt"], c
        assert c[-6:] == ["-t", rf"{TPL}\ssl", "-severity", "high", "-tags", "arcgis"], c
        assert all(set(p[0]) <= set(CATS) and p[4] <= set(MODULES) and (p[0] or p[4]) for p in PRESETS.values())
        assert DEFAULT_PRESET in PRESETS and PRESET_HELP.keys() == PRESETS.keys()
        assert all(preset_details(p) for p in PRESETS) and "INTRUSIVE" in preset_details("Full Scan / ตรวจเต็ม")
        assert parse_ports("22,8000-8002") == [22, 8000, 8001, 8002] and 3389 in parse_ports("top")
        assert len(parse_ports("all")) == 65535 and 8081 in parse_ports("top,8081")
        for bad in ("0", "70000", "9-3", "abc"):
            try:
                parse_ports(bad); raise AssertionError(bad)
            except ValueError:
                pass
        assert target_host("https://a.com:8443/x") == "a.com" and target_host("1.2.3.4") == "1.2.3.4"
        hf, hr = header_findings("https://a", 200, {"server": "Microsoft-IIS/8.5", "x-powered-by": "ASP.NET",
                                                    "x-forwarded-for": "10.0.0.5", "content-encoding": "gzip",
                                                    "x-content-type-options": "nosniff", "x-frame-options": "DENY"},
                                 ["sid=1; path=/", "ok=1; Secure; HttpOnly; SameSite=Lax"], "headers", "gzip")
        ids = {f["template-id"] for f in hf}
        assert {"hdr-hsts", "hdr-csp", "hdr-server-version", "hdr-tech-banner", "hdr-proxy-banner", "hdr-internal-ip",
                "hdr-xfh-reflect", "hdr-cookie-flags", "hdr-breach"} <= ids, ids
        assert not ids & {"hdr-xfo", "hdr-xcto", "hdr-cors"}, ids
        assert ("Cookies", "ok", "Secure; HttpOnly; SameSite (OK)", "OK") in hr
        hf, _ = header_findings("https://a", 200, {"server": "", "x-powered-by": "", "strict-transport-security": "max-age=1",
                                                   "x-forwarded-for": "", "x-aspnet-version": ""}, [], "", "")
        assert not {f["template-id"] for f in hf} & {"hdr-hsts", "hdr-server-version", "hdr-tech-banner", "hdr-proxy-banner"}
        rows = [{"template-id": "x", "host": "https://a", "matched-at": "https://a/1", "info": {"name": "<b>XSS</b>", "severity": "high"}},
                {"template-id": "x", "host": "https://b", "info": {"name": "<b>XSS</b>", "severity": "high"}},
                {"template-id": "y", "host": "https://a", "info": {"name": "Tech", "severity": "info", "reference": "https://r"}},
                {"template-id": "z", "host": "https://b", "info": {"name": "Crit", "severity": "critical"}}]
        assert [k for k, _ in group(rows, lambda r: r["template-id"])] == ["z", "x", "y"]
        assert counts(rows) == {"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 1}
        assert "https://a/1" in detail_text(group(rows, lambda r: r["template-id"])[1][1])
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "findings.jsonl"), "w") as fh:  # last line half-written, like a live scan
            fh.write("\n".join(json.dumps(r) for r in rows) + '\n{"template-id": "par')
        assert len(load_findings(d)) == 4
        write_meta(d, name="t", status="running"); write_meta(d, status="completed")
        assert read_meta(d) == {"name": "t", "status": "completed"}
        with open(os.path.join(d, "tls.json"), "w") as fh:
            json.dump({"a:443": [["Protocols", "SSLv3", "offered <x>", "HIGH"], ["Protocols", "TLS 1.3", "offered (OK)", "OK"]],
                       "b:443": {"grade": {"grade": "B"}, "rows": [["Rating", "Score", "85 / 100", "INFO"]],
                                 "ciphers": [{"protocol": "TLS 1.2", "name": "TLS_X<", "openssl": "X", "kx": "ECDH 256",
                                              "bits": 128, "strength": "strong", "status": "OK"}]}}, fh)
        out = open(make_html(d, ["https://a"]), encoding="utf-8").read()
        assert "SSL/TLS (testssl-style)" in out and "offered &lt;x&gt;" in out and out.count('class="sec"') == 2 and "TLS_X&lt;" in out             and ">B</span>" in out, "tls table"
        with open(os.path.join(d, "ports.json"), "w") as fh:
            json.dump({"a": [{"port": 3389, "service": "RDP", "banner": "<x>", "severity": "high", "note": "n"}]}, fh)
        with open(os.path.join(d, "headers.json"), "w") as fh:
            json.dump({"https://a": {"rows": [["Banners", "Server", "IIS/8.5", "LOW"]]}}, fh)
        out = open(make_html(d, ["https://a"]), encoding="utf-8").read()
        assert "<td>3389</td>" in out and "&lt;x&gt;" in out and "HTTP headers (testssl-style)" in out and "IIS/8.5" in out
        assert "&lt;b&gt;XSS" in out and "<b>XSS" not in out and out.index("Crit") < out.index("XSS") < out.index("Tech")
        assert "No findings" in open(make_html(tempfile.mkdtemp(), []), encoding="utf-8").read()
        shutil.rmtree(d)
        cs = lambda n, b=128, fs=True: {"name": n, "bits": b, "kx_type": "ECDH" if fs else "", "kx_size": 256 if fs else 0,
                                         "strength": cipher_strength(n, b, False, fs)[0]}
        good = [cs("TLS_AES_256_GCM_SHA384", 256), cs("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")]
        cert = {"bits": 2048, "ec": False, "untrusted": False, "expired": False, "sha1": False}
        flags = {"heartbleed": False, "ccs": False, "robot": False, "compression": False, "insecure_reneg": False,
                 "hsts_age": 31536000, "no_scsv": False}
        assert tls_grade(["TLS 1.2", "TLS 1.3"], good, cert, flags)["grade"] == "A+"
        assert tls_grade(["TLS 1.2", "TLS 1.3"], good, cert, {**flags, "hsts_age": 0})["grade"] == "A"
        assert tls_grade(["TLS 1.0", "TLS 1.2", "TLS 1.3"], good, cert, flags)["grade"] == "B"
        assert tls_grade(["TLS 1.2"], good + [cs("TLS_RSA_WITH_3DES_EDE_CBC_SHA", 112, False)], cert, flags)["grade"] == "C"
        assert tls_grade(["TLS 1.2", "TLS 1.3"], good, cert, {**flags, "heartbleed": True})["grade"] == "F"
        g = tls_grade(["TLS 1.2", "TLS 1.3"], good, {**cert, "untrusted": True}, flags)
        assert g["grade"] == "T" and g["grade_ignoring_trust"] == "A+", g
        assert tls_grade([], [], cert, flags)["grade"] == "-"
        assert cipher_strength("TLS_RSA_WITH_RC4_128_SHA", 128, False, False)[1] == "HIGH"
        assert cipher_strength("TLS_RSA_WITH_AES_128_GCM_SHA256", 128, False, False)[1] == "LOW"
        assert cipher_strength("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 128, False, True)[0].startswith("OK (CBC")
        assert tls_endpoint("https://a.com/x") == ("a.com", 443) and tls_endpoint("a.com:8443") == ("a.com", 8443)
        assert tls_endpoint("http://a.com") is None and tls_endpoint("http://a.com:8443") == ("a.com", 8443)
        print("ok"); sys.exit()
    App().mainloop()
