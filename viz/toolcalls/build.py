#!/usr/bin/env python3
"""Build the self-contained chart page from the template and the two datasets.

Injects ``datasets/summary.json`` as ``DATA`` and ``datasets/detail.json`` as ``DETAIL``
into ``chart.template.html`` and writes ``index.html`` (deployable as-is).

    python3 viz/toolcalls/build.py
"""
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main():
    html = (HERE / "chart.template.html").read_text(encoding="utf-8")
    data = (HERE / "datasets/summary.json").read_text(encoding="utf-8").strip()
    detail = (HERE / "datasets/detail.json").read_text(encoding="utf-8").strip()
    html = html.replace("__DATA__", data).replace("__DETAIL__", detail)
    assert "__DATA__" not in html and "__DETAIL__" not in html, "placeholder left unfilled"
    assert html.count("</script") == 1, "a data value contains </script — would break the page"
    out = HERE / "index.html"
    out.write_text(html, encoding="utf-8")
    print(f"wrote {out} ({len(html)} bytes)")


if __name__ == "__main__":
    main()
