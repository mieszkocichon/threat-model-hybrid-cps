"""Ablacja osi granicy zaufania: mapowanie warunkowane granica vs mapowanie plaskie.

Wejscie : stride_attck_mapping.csv, risk_scoring.csv (artefakty uzupelniajace pracy)
Wyjscie : baseline_ablation.txt (liczby cytowane w Sekcji "Ablacja osi granicy")

Baseline jest zdefiniowany jako NAJLEPSZE mozliwe mapowanie plaskie: dla kazdej
kategorii STRIDE wybieramy te jedna technike, ktora maksymalizuje odzysk technik
zweryfikowanych przez MITRE dla czterech incydentow walidacyjnych. Porownujemy sie
wiec z gornym ograniczeniem podejscia plaskiego, a nie z jego dowolna instancja --
inaczej wynik zalezalby od tego, ktora publikacje wybierzemy jako punkt odniesienia.
"""

import csv
import itertools
from collections import defaultdict

STRIDE_ORDER = ["Spoofing", "Tampering", "Repudiation",
                "Information Disclosure", "DoS", "Elevation of Privilege"]

# Techniki badane przez studia przypadkow (Sekcja "Walidacja"), kazda zweryfikowana
# jako przypisana przez MITRE do danego incydentu. NIE sa to pelne zbiory MITRE:
# S0603 liczy 25 technik, S1009 18, S0604 25. Studia przypadkow analizuja podzbior
# odpowiadajacy kinetycznej sciezce incydentu i to on jest tu odwzorowany; ablacja
# mierzy odzysk wzgledem tego podzbioru i tak nalezy ja czytac.
# Zrodla: S0603 (Stuxnet), S1009 (Triton), S0604 (Industroyer), CISA AA21-131A (Colonial).
# Uwaga: MITRE przypisuje Tritonowi T1693.001 (System Firmware), nie rodzica T1693;
# C0030 nie zawiera zadnej z pieciu technik Tritona ponizej - wlasciwym zrodlem jest S1009.
# Baseline A (STRIDE-per-element). Klasyczny STRIDE nakladany na elementy diagramu
# DFD nie zna osi granicy, zna natomiast element, ktorego zagrozenie dotyczy. Kazdej
# granicy przypisujemy wiec jej element WEWNETRZNY (chroniony), czyli ten, do ktorego
# przeplyw dociera; zagrozenie jest wyliczane per (kategoria, element). Regula ta
# zwija B1/B2 do Chmury oraz B5/B6 do PLC, bo w obu parach ten sam element jest celem.
ELEMENT_INNER = {"B1": "Chmura", "B2": "Chmura", "B3": "Brama brzegowa",
                 "B4": "Siec OT", "B5": "PLC", "B6": "PLC", "B7": "SIS"}
# Wariant scislejszy (analiza wrazliwosci): PLC terminuje takze B7, wiec przejmuje
# jego zagrozenia zamiast SIS. Odpowiada dekompozycji, w ktorej SIS nie jest
# wyodrebnionym elementem DFD.
ELEMENT_STRICT = dict(ELEMENT_INNER, B7="PLC")

INCIDENT_TECHNIQUES = {
    "Stuxnet":      {"T0835", "T0832", "T0873.001", "T0843"},
    "Triton":       {"T0858", "T0843", "T0845", "T1693.001", "T0880"},
    "Industroyer":  {"T0831", "T0813", "T0815", "T0809", "T0800"},
    "Colonial":     {"T0859"},
}


def parent(tid):
    """Podtechnika liczy sie jako odzyskana przez wiersz wskazujacy jej rodzica.

    Bez tej normalizacji T1693.001 (Triton) nie zrownalby sie z wierszem T1693
    na B4, mimo ze wiersz wskazuje dokladnie te rodzine technik.
    """
    return tid.split(".")[0]


def norm(techs):
    return {parent(t) for t in techs if t}


def per_element_best(mapping, element_of, all_incident):
    """Baseline A: najlepsze mozliwe mapowanie STRIDE-per-element.

    Jedna technika na komorke (kategoria, element). Komorki sa niezalezne, wiec
    najlepszy przypadek uzyskuje sie wybierajac w kazdej z nich technike incydentowa,
    o ile taka w niej wystepuje. Zwraca (odzyskane techniki, liczba komorek).
    """
    cells = defaultdict(set)
    for r in mapping:
        tid = r["Technique_ID"].strip()
        if not tid:
            continue
        key = (r["STRIDE_Category"].strip(), element_of[r["Trust_Boundary"].strip()])
        cells[key].add(tid)

    inc_parents = norm(all_incident)
    # Komorka moze oddac tylko jedna technike, nawet jesli trafia w kilka incydentowych.
    # Przeszukujemy wyczerpujaco kombinacje wyborow w komorkach, ktore w ogole trafiaja,
    # zeby baseline byl dobrany na swoja korzysc (best case), a nie zachlannie.
    hit_cells = []
    for techs in cells.values():
        hits = sorted({parent(t) for t in techs if parent(t) in inc_parents})
        if hits:
            hit_cells.append(hits)

    best = set()
    for combo in itertools.product(*hit_cells):
        got = {t for t in all_incident if parent(t) in set(combo)}
        if len(got) > len(best):
            best = got
    return best, len(cells)


def load(path):
    with open(path, encoding="utf-8") as f:
        return [r for r in csv.DictReader(f) if r["STRIDE_Category"].strip()]


def main():
    mapping = load("stride_attck_mapping.csv")
    scoring = load("risk_scoring.csv")

    # --- struktura mapowania warunkowanego granica ---------------------------
    by_cat = defaultdict(list)          # kategoria -> [(granica, technika)]
    for r in mapping:
        tid = r["Technique_ID"].strip()
        by_cat[r["STRIDE_Category"].strip()].append((r["Trust_Boundary"].strip(), tid))

    # severity / AV per (kategoria, granica) z risk_scoring
    sev = defaultdict(set)
    av = defaultdict(set)
    for r in scoring:
        cat = r["STRIDE_Category"].strip()
        sev[cat].add(r["Severity"].strip())
        av[cat].add(r["CVSS_AttackVector_derived"].strip())

    bc_rows = len(mapping)
    bc_techs = {t for rows in by_cat.values() for _, t in rows if t}

    lines = []
    add = lines.append
    add("=" * 78)
    add("ABLACJA OSI GRANICY ZAUFANIA")
    add("=" * 78)
    add("")
    add(f"Wierszy mapowania warunkowanego granica : {bc_rows}")
    add(f"Odrebnych technik ATT&CK for ICS        : {len(bc_techs)}")
    add(f"Kategorii STRIDE                        : {len(by_cat)}")
    add("")
    add("Kazde mapowanie plaskie przypisuje dokladnie jedna technike na kategorie")
    add(f"STRIDE, wiec jego obraz ma co najwyzej {len(by_cat)} technik -- niezaleznie od tego,")
    add("ktora publikacje przyjmiemy za punkt odniesienia. Jest to ograniczenie")
    add("strukturalne podejscia plaskiego, nie artefakt naszego doboru baseline'u.")
    add("")

    # --- per kategoria: multiplicity ----------------------------------------
    add("-" * 78)
    add("TABELA A. Rozdzielczosc odbierana przez zwiniecie osi granicy")
    add("-" * 78)
    add(f"{'Kategoria STRIDE':<24}{'granice':<9}{'techniki':<10}{'powagi':<9}{'AV':<5}")
    nonconst = 0
    sev_div = 0
    av_div = 0
    table_a = []
    for cat in STRIDE_ORDER:
        rows = by_cat.get(cat, [])
        bounds = {b for b, _ in rows}
        techs = {t for _, t in rows if t}
        n_t, n_s, n_a = len(techs), len(sev[cat]), len(av[cat])
        if n_t > 1:
            nonconst += 1
        if n_s > 1:
            sev_div += 1
        if n_a > 1:
            av_div += 1
        table_a.append((cat, len(bounds), n_t, n_s, n_a))
        add(f"{cat:<24}{len(bounds):<9}{n_t:<10}{n_s:<9}{n_a:<5}")
    add("")
    add(f"Kategorie niestale wzgledem granicy (>1 technika) : {nonconst}/{len(STRIDE_ORDER)}")
    add(f"Kategorie o rozbieznej powadze  (>1 powaga)       : {sev_div}/{len(STRIDE_ORDER)}")
    add(f"Kategorie o rozbieznym AV       (>1 AV)           : {av_div}/{len(STRIDE_ORDER)}")
    add("")

    # --- odzysk technik incydentow ------------------------------------------
    all_incident = set().union(*INCIDENT_TECHNIQUES.values())
    bc_norm = norm(bc_techs)
    bc_recovered = {t for t in all_incident if parent(t) in bc_norm}

    # najlepsze mozliwe mapowanie plaskie: 1 technika na kategorie, maksymalizacja odzysku
    choices = []
    for cat in STRIDE_ORDER:
        techs = sorted({t for _, t in by_cat.get(cat, []) if t})
        choices.append(techs if techs else [None])

    best_set, best_combo = set(), None
    for combo in itertools.product(*choices):
        cn = norm(combo)
        got = {t for t in all_incident if parent(t) in cn}
        if len(got) > len(best_set):
            best_set, best_combo = got, combo

    # Baseline A: STRIDE-per-element (dwa warianty przypisania elementu)
    pe_set, pe_cells = per_element_best(mapping, ELEMENT_INNER, all_incident)
    pe_strict, pe_strict_cells = per_element_best(mapping, ELEMENT_STRICT, all_incident)

    add("-" * 78)
    add("TABELA B. Odzysk technik zweryfikowanych przez MITRE dla incydentow")
    add("-" * 78)
    add(f"{'Incydent':<16}{'technik MITRE':<16}{'warunk. granica':<18}"
        f"{'per-element':<14}{'plaskie (best)':<16}")
    for inc, techs in INCIDENT_TECHNIQUES.items():
        add(f"{inc:<16}{len(techs):<16}{len(techs & bc_recovered):<18}"
            f"{len(techs & pe_set):<14}{len(techs & best_set):<16}")
    add(f"{'RAZEM':<16}{len(all_incident):<16}{len(bc_recovered):<18}"
        f"{len(pe_set):<14}{len(best_set):<16}")
    add("")
    add("BASELINE A (STRIDE-per-element, best case). Element wewnetrzny granicy;")
    add(f"    komorek (kategoria, element) : {pe_cells}  wobec {bc_rows} wierszy warunkowanych granica")
    add(f"    odzysk                       : {len(pe_set)}/{len(all_incident)} "
        f"({100*len(pe_set)/len(all_incident):.0f}%)")
    add(f"    nieodzyskane                 : {', '.join(sorted(all_incident - pe_set)) or '(brak)'}")
    add("    Wariant scislejszy (PLC terminuje takze B7, SIS nie jest odrebnym elementem):")
    add(f"    komorek {pe_strict_cells}, odzysk {len(pe_strict)}/{len(all_incident)} "
        f"({100*len(pe_strict)/len(all_incident):.0f}%)")
    add("")
    add("UWAGA INTERPRETACYJNA. Na odzysku technik incydentowych baseline per-element")
    add("nie rozni sie od mapowania warunkowanego granica; przewaga osi granicy jest")
    add("przewaga ROZDZIELCZOSCI (liczba komorek i odrebnych technik), nie odzysku.")
    add("Roznica wobec mapowania PLASKIEGO pozostaje duza w obu wymiarach.")
    add("")
    add(f"Najlepsze mapowanie plaskie (dobrane tak, by maksymalizowac odzysk):")
    for cat, t in zip(STRIDE_ORDER, best_combo):
        add(f"    {cat:<24} -> {t if t else '(brak odpowiednika)'}")
    add("")
    add(f"Odzysk warunkowany granica : {len(bc_recovered)}/{len(all_incident)} "
        f"({100*len(bc_recovered)/len(all_incident):.0f}%)")
    add(f"Odzysk plaski (best case)  : {len(best_set)}/{len(all_incident)} "
        f"({100*len(best_set)/len(all_incident):.0f}%)")
    add("")
    only_bc = sorted(bc_recovered - best_set)
    add("Techniki odzyskane wylacznie dzieki warunkowaniu granica:")
    add("    " + (", ".join(only_bc) if only_bc else "(brak)"))
    add("")
    missed = sorted(all_incident - bc_recovered)
    add("UWAGA. Techniki nieodzyskane przez zadne z podejsc: "
        + (", ".join(missed) if missed else "(brak)"))
    if missed:
        add("Nie jest to decyzja zakresowa: studia przypadkow lokalizuja kazda z nich")
        add("na granicy nalezacej do modelu, wiec w sensie tabeli walidacyjnej sa")
        add("pokryte. Odpowiadajace im komorki macierzy P3 SA rozstrzygniete, lecz na")
        add("rzecz techniki realizujacej dana kategorie STRIDE bardziej bezposrednio.")
        add("Odzyskanie ich wymagaloby przypisania komorce zbioru technik zamiast")
        add("jednej - co macierz juz dopuszcza (Tampering na B4) i czego domkniecie")
        add("pozostaje praca w toku.")
    else:
        add("Po domknieciu macierzy P3 do 39 z 42 komorek mapowanie warunkowane")
        add("granica odzyskuje kazda technike badana przez studia przypadkow.")
    add("")

    out = "\n".join(lines)
    print(out)
    with open("baseline_ablation.txt", "w", encoding="utf-8") as f:
        f.write(out + "\n")

    # --- kontrola poprawnosci ------------------------------------------------
    assert len(bc_techs) > len(STRIDE_ORDER), \
        "mapowanie warunkowane musi dawac wiecej technik niz jest kategorii STRIDE"
    assert len(best_set) <= len(bc_recovered), \
        "baseline nie moze odzyskac wiecej niz mapowanie warunkowane"
    assert best_set <= bc_recovered, \
        "baseline wybiera wylacznie sposrod technik obecnych w mapowaniu"
    assert best_set <= pe_set, \
        "baseline per-element jest co najmniej tak silny jak plaski (zwiekszona ziarnistosc)"
    assert pe_set <= bc_recovered, \
        "zaden baseline nie moze odzyskac techniki nieobecnej w mapowaniu warunkowanym"
    assert pe_cells < bc_rows, \
        "per-element musi miec mniej komorek niz mapowanie warunkowane ma wierszy"
    print("[ok] kontrole spojnosci przeszly")


if __name__ == "__main__":
    main()
