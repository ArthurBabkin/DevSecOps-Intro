#!/usr/bin/env python3
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from xml.dom import minidom


def txt(parent, tag, val):
    e = ET.SubElement(parent, tag)
    e.text = "" if val is None else str(val)
    return e


def main() -> int:
    src = Path(sys.argv[1] if len(sys.argv) > 1 else "labs/lab5/zap/zap-report-noauth.json")
    dst = Path(sys.argv[2] if len(sys.argv) > 2 else "labs/lab10/imports/zap-report-noauth.xml")
    d = json.loads(src.read_text(encoding="utf-8"))
    root = ET.Element("OWASPZAPReport")
    root.set("version", str(d.get("@version", "2.0.0")))
    root.set("generated", str(d.get("created", d.get("@generated", ""))))

    for site in d.get("site", []):
        s = ET.SubElement(root, "site")
        nm = site.get("@name") or site.get("name") or ""
        s.set("host", str(site.get("@host", site.get("host", ""))))
        s.set("port", str(site.get("@port", site.get("port", ""))))
        s.set("ssl", str(site.get("@ssl", site.get("ssl", "false"))))
        s.set("name", str(nm))
        alerts = ET.SubElement(s, "alerts")
        for a in site.get("alerts", []):
            it = ET.SubElement(alerts, "alertitem")
            txt(it, "pluginid", a.get("pluginid", ""))
            txt(it, "alert", a.get("alert") or a.get("name", ""))
            txt(it, "desc", a.get("desc", ""))
            txt(it, "riskcode", str(a.get("riskcode", "0")))
            txt(it, "confidence", str(a.get("confidence", "2")))
            txt(it, "solution", a.get("solution", ""))
            txt(it, "reference", a.get("reference", ""))
            cw = a.get("cweid")
            txt(it, "cweid", str(cw) if cw not in (None, "") else "")
            insts = ET.SubElement(it, "instances")
            for x in a.get("instances", []):
                i = ET.SubElement(insts, "instance")
                txt(i, "uri", x.get("uri", ""))
                txt(i, "method", x.get("method", ""))
                txt(i, "param", x.get("param", ""))
                txt(i, "attack", x.get("attack", ""))
                txt(i, "evidence", x.get("evidence", ""))

    raw = ET.tostring(root, encoding="utf-8")
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(minidom.parseString(raw).toprettyxml(indent="  ", encoding="utf-8"))
    print(dst, dst.stat().st_size)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
