# Lagplan: snabbast och bäst från 15:00

Skriven 20 oktober 2026 (efter dag 20) för de fyra i laget. Planen bygger på robotens
loggar från Homebase och på reglerna i `AGENTS.md`. Hur vi arbetar i repot står i
`CLAUDE.md`; läs den först.

## Vad som räknas

- **Hall of Fame mäter varje tidsatt försöks egen klocka** (`run_for_time:true`), från
  serverns `started_at` till inlämningen. Den mäter inte tiden sedan släppet. Ett lopp
  kan köras när som helst, men bara om lösaren redan finns: deadlinen är 50 s för
  Time Trial och 115–170 s för Mastery (`ranked_deadline_ms`), så en AI som tänker
  under loppet hinner inte.
- **Poäng ges för varje korrekt lösning** (CourseStack). Ett otidsatt försök ger samma
  flagga och poäng.
- **Lagkamrater delar försök och framsteg** (`AGENTS.md`, rad 15). Därför får bara
  **en** robot i laget starta, försöka igen och lämna in. Övriga analyserar och skriver
  lösare.

Målet blir alltså:

1. Så många frågetyper som möjligt ska vara kodade *före* 15:00, så att roboten löser
   dem direkt.
2. Nya frågetyper ska bli lösare snabbt, med en ägare per lane.
3. Varje lopp ska ta så få millisekunder som möjligt på klockan.

## Vad som hände på dag 20

| Svensk tid | Händelse |
| --- | --- |
| 15:01:50 | En robot som startats för hand löser Warmups dag 20 och startar Metadata. |
| 15:02:00 | `day.sh` (cron) startar samtidigt. Två robotar kör på samma försök. |
| 15:02:00–15:02:37 | Otidsatt körning, en uppgift i taget: Metadata, Script, Binary och Android blir `unresolved`. Time Trial och Mastery låses (HTTP 409, Single Solve måste lösas först). |
| 15:02:37–15:02:53 | Tidsatta lopp: bara Warmups har bevisade lösare. |
| därefter | Inget mer. Dagen är markerad som klar, så inget körs om fast en lösare skulle dyka upp. |

| Uppgift | Frågor (typer) | Resultat | Varför |
| --- | --- | --- | --- |
| Warmups TT | 1 | **285 ms på klockan** (bästa hittills) | Kedjan var känd; lösningen tog 0,5 ms |
| Warmups Mastery | 98 | 820 ms (2 712 ms till svaret) | Nedladdning 726 ms; servern rättar i 1,9 s |
| Metadata "Universal Appeal" | 1 (1) | olöst | Ny typ `macho.cpu_type_set`; ingen Mach-O-parser |
| Script "Jenkins Pipeline" | 1 329 (82) | olöst | Lanen saknas; lösarna letade i 579 ms utan träff |
| Binary "Resources and Overlays" | 240 (16) | olöst | Lanen saknas; **33 MB tog 8,4 s att ladda ned** |
| Android "Loaded Later" | 1 (1) | olöst | Lanen saknas |
| Web Mastery dag 4 och 5 | – | HTTP 400 `invalid_delivery` | Roboten försöker hämta en fil fast uppgiften bara har `targets[]` (själva starten tog 4,8 s medan servern förberedde målet) |

Gamla frågor att lära från (dag 1–19): Script 73 171, Binary 11 665, Warmups 950 (alla
klaras), Metadata 923 (alla klaras), Android 109. Mastery återanvänder äldre dagars
typer. Av dagens 240 Binary-frågor gällde 170 ZIP-poster i central-directory-ordning,
alltså en gammal typ. **Varje gammal typ vi kodar gäller därför också framtida dagar.**

## Uppdelning: en ägare per lane

| Vem | Ansvar | Storlek | Första uppgift |
| --- | --- | --- | --- |
| Person 1 | **Script Analysis** | störst (1 329 frågor idag) | Gruppera dag 20:s 82 typer och dag 1–19 efter typ; börja med de vanligaste ("Recover the exact synthetic campaign identifier", stage count, behavior graph, MITRE-mappning) |
| Person 2 | **Binary** (subagent `ctf-binary`) | stor (240 idag) | Arkitektur per levererad binär (25 frågor), resurser och overlay; återanvänd ZIP-delen från `metadata.py` |
| Person 3 | **Metadata + Android** | liten, men en ny typ per dag | Mach-O `macho.cpu_type_set` (dag 20, 1 fråga); Android dag 20 (subagent `ctf-android`) |
| Person 4 | **Releasemotorn + Web** | infrastruktur | P0-punkterna nedan; därefter Web Exploitation (live-mål, ingen fil) |

## Förbättringar i prioritetsordning

### P0: före 15:00 i morgon (dag 21)

1. **En robot per lag, även för hand.** Låset i `day.sh` gäller bara skriptet. Lägg
   låset i Python (`~/.huntress/robot.lock`) runt allt som anropar start, retry och
   submit, så att en körning för hand väntar eller avbryts med ett tydligt besked.
2. **Kör lanes parallellt.** `daily` kör uppgifterna en i taget (`daily.py`, rad 76).
   Kör varje uppgiftsfamilj (Single Solve, Time Trial, Mastery i den ordningen) i en
   egen tråd med egen anslutning. Idag tog den otidsatta delen 37 s; parallellt blir det
   ungefär den längsta kedjan (Binary, cirka 13 s).
3. **Börja exakt 15:00:00.** `day.sh` sover till 15:02. Fråga i stället `list --day N
   --lane <lane>` (~1 s per anrop) från 15:00:00 tills den nya dagen syns, och starta
   sedan direkt.
4. **Fortsätt efter första svepet.** Byt markeringen "dagen klar" mot en ny körning var
   15:e minut så länge dagen har olösta uppgifter. Då löser roboten själv Single Solve
   och kör loppet när någon pushar en ny lösare och driftsätter den. Tidsatta lopp får
   bara köras en gång per rutt och dag. Spara bästa tid i `hints.json`, så att varje
   körning inte förbrukar en tidsatt variant (32 för dagens Metadata-rutter, 256 för
   Warmups).
5. **Web: hoppa över filhämtningen** när start-svaret har `targets[]`. Då rapporteras
   rutten som olöst i stället för som fel, och ett meningslöst anrop försvinner.
6. **Mach-O i `metadata.py` och `artifacts.py`** (`macho.cpu_type_set`): triage kallade
   filen "unrecognized binary data". Fat-header `0xCAFEBABE`, thin
   `0xFEEDFACE`/`0xFEEDFACF`. Ordning och namnformat för CPU-typerna är okända;
   bekräfta dem med `learn`.

### P1: den här veckan

7. **Lane-lösarna** enligt uppdelningen ovan. Gör en parser per frågetyp och inte per
   dag. Testa mot gamla frågor offline.
8. **Bara relevanta lösare på klockan.** Script- och Binary-lösarna letade i ~600 ms
   utan att hitta något. Välj lösare efter lane och frågetyp; målet är under 30 ms.
   Mät med `triage <fil> --time --question "..."`.
9. **Stora filer.** 33 MB genom proxyn tog 8,4 s (~4 MB/s). Mät den direkta vägen mot
   proxyn och om HTTP Range går att dela upp på flera anslutningar. Ta reda på om
   servern kompenserar (`ranked_reference_bytes_per_second` = 1 MiB/s,
   `ranked_transfer_allowance_ms` 600 för TT och 3 000 för Mastery).
10. **Kortare utskrift.** Loggen blev 2,2 MB eftersom uppgiften skrivs ut två gånger
    (16 000 rader för Script). Skriv ut den en gång och sammanfatta när frågorna är fler
    än ~50. Hela listan finns redan i `work/<id>/assignment.json`, så kravet på full
    insyn i `AGENTS.md` uppfylls ändå.

### P2: när P0 och P1 är klara

11. **Vilken klocka gäller?** Jämför tiden i Hall of Fame med robotens `from`/`to`
    (idag TT 285/840 ms, Mastery 820/2 712 ms). Stämmer `to` räknas serverns rättning
    på 1,9 s, och då lönar det sig att dela upp Mastery-inlämningen.
12. **Gemensam hints-källa.** `hints.json` finns på PC:n och på Homebase och glider
    isär. Den Homebase som spelar är sanningen.

## Arbetssätt i laget

- **Gren per lane**, till exempel `lane/script-analysis`, och PR till `main`. Alla
  tester måste passera: `python -m unittest discover -s tests`.
- **Ett lösarbyte är klart först när** (1) `solvers/<lane>.py` finns med ett syntetiskt
  test, (2) testet passerar och (3) `solve <id>` når CORRECT live på den Homebase som
  spelar.
- **Analysera utan att spela:** läs `work/<id>/triage.md` och `assignment.json` från den
  spelande Homebase, eller kör `triage <fil>` offline. På din egen Homebase är `status`
  och `artifact` läs-only. `start`, `retry`, `submit` och `learn` förbrukar eller
  ändrar lagets försök: säg till i lagchatten först.
- **Aldrig i git:** riktiga artefakter, svar, flaggor, tokens och `.huntress/` (allt
  ignoreras redan).
- **Driftsätt** på den spelande Homebase: `scp -r .\src HuntressCTF@<ip>:~/` och
  `scripts/homebase-day.sh` till `~/day.sh` (installationen står i skriptets huvud).
