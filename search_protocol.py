"""Protokol wyszukiwania dla Sekcji "Prace pokrewne" (odtwarza liczby cytowane w tekscie).

Baza  : OpenAlex REST API (metadane IEEE, Elsevier, ACM, Springer, MDPI)
Okno  : 2015-01-01 .. 2026-08-08, pola tytulu i abstraktu
Wynik : search_protocol.txt

NIE jest to przeglad systematyczny w rozumieniu PRISMA: pojedyncza baza, brak
drugiego oceniajacego, screening ograniczony do tytulu i abstraktu. Celem jest
uczynienie zakresu twierdzenia o nowosci sprawdzalnym, nie wyczerpanie literatury.

Uwaga o odtwarzalnosci: OpenAlex jest baza zywa, wiec liczby moga sie zmienic
przy pozniejszym uruchomieniu. Liczby raportowane w manuskrypcie pochodza
z uruchomienia z 2026-08-08 i sa zapisane w RUN_2026_08_08 ponizej.
"""

import html
import json
import re
import sys
import time
import urllib.parse
import urllib.request

WINDOW = "from_publication_date:2015-01-01,to_publication_date:2026-08-08"

QUERIES = {
    "Q1": 'STRIDE AND ATT&CK',
    "Q2": 'STRIDE AND (ICS OR "industrial control")',
    "Q3": 'ATT&CK AND "cyber-physical" AND (cloud OR edge)',
    "Q4": '"trust boundary" AND "threat model" AND (ICS OR "industrial control")',
}

# Screening tytulow: rekord przechodzi, jesli tytul zawiera termin z domeny
# bezpieczenstwa. Wyklucza glownie homonim "stride" (dlugosc kroku) w biomechanice.
SECURITY_TERMS = r"threat|stride|att&ck|attack|security|cyber|ics|scada|risk|vulnerab|mitre|malware|intrusion"
# I1: taksonomia jest przedmiotem pracy (wskaznik operacyjny: nazwa w tytule)
I1 = r"stride|att&ck|attck|mitre|d3fend"
# I2: domena ICS/OT/CPS
I2 = r"\bics\b|industrial control|scada|cyber.physical|\bot\b|substation|plc|water|power plant|oil|gas|smart grid|iiot"

# Liczby raportowane w manuskrypcie (uruchomienie 2026-08-08).
RUN_2026_08_08 = {"Q1": 69, "Q2": 91, "Q3": 17, "Q4": 3,
                  "raw": 180, "dedup": 162, "po_tytule": 103, "I1": 20, "I2": 8}


def fetch(query):
    url = ("https://api.openalex.org/works?filter=" + WINDOW
           + ",title_and_abstract.search:" + urllib.parse.quote(query)
           + "&per-page=200&select=id,display_name,publication_year,doi")
    with urllib.request.urlopen(url, timeout=60) as f:
        return json.load(f)


def main():
    lines = []
    add = lines.append
    records = {}

    add("PROTOKOL WYSZUKIWANIA -- OpenAlex, okno 2015-01-01..2026-08-08")
    add("=" * 78)
    for key, query in QUERIES.items():
        data = fetch(query)
        for w in data["results"]:
            records.setdefault(w["id"], {"t": html.unescape(w["display_name"] or ""),
                                         "y": w["publication_year"],
                                         "doi": w.get("doi"), "q": []})["q"].append(key)
        add(f"{key}  {query}")
        add(f"     trafien: {data['meta']['count']}")
        time.sleep(1)

    raw = sum(len(v["q"]) for v in records.values())
    screened = [v for v in records.values() if re.search(SECURITY_TERMS, v["t"], re.I)]
    i1 = [v for v in screened if re.search(I1, v["t"], re.I)]
    i2 = [v for v in i1 if re.search(I2, v["t"], re.I)]

    add("")
    add(f"Rekordow surowych                       : {raw}")
    add(f"Po deduplikacji                         : {len(records)}")
    add(f"Po screeningu tytulow (termin domenowy) : {len(screened)}"
        f"   (odrzucono {len(records) - len(screened)}, gl. homonim 'stride')")
    add(f"I1 -- taksonomia w tytule               : {len(i1)}")
    add(f"I2 -- domena ICS/OT/CPS                 : {len(i2)}  <- zbior kwalifikowany")
    add("")
    add("ZBIOR KWALIFIKOWANY")
    add("-" * 78)
    for v in sorted(i2, key=lambda x: x["y"]):
        add(f"{v['y']}  {v['t'][:88]}")
        add(f"        {v['doi'] or 'brak DOI'}   [{','.join(v['q'])}]")

    add("")
    add("Zgodnosc z liczbami raportowanymi w manuskrypcie (uruchomienie 2026-08-08):")
    now = {"raw": raw, "dedup": len(records), "po_tytule": len(screened),
           "I1": len(i1), "I2": len(i2)}
    for k, v in now.items():
        ref = RUN_2026_08_08[k]
        add(f"    {k:<12} teraz {v:<5} w manuskrypcie {ref:<5} {'zgodne' if v == ref else 'ROZNICA -- baza zywa, zaktualizuj tekst'}")

    out = "\n".join(lines)
    # tytuly z bazy zawieraja znaki spoza kodowania konsoli Windows (np. U+2010)
    print(out.encode(sys.stdout.encoding or "utf-8", "replace")
             .decode(sys.stdout.encoding or "utf-8"))
    with open("search_protocol.txt", "w", encoding="utf-8") as f:
        f.write(out + "\n")

    assert len(i2) <= len(i1) <= len(screened) <= len(records), \
        "kaskada selekcji musi byc monotoniczna"


if __name__ == "__main__":
    main()
