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
   **Klart (`lock.py`):** andra roboten stoppas och får veta vem som håller låset,
   eller väntar med `--lock-wait`; `day.sh` väntar upp till en timme.
2. **Kör lanes parallellt.** `daily` kör uppgifterna en i taget (`daily.py`, rad 76).
   Kör varje uppgiftsfamilj (Single Solve, Time Trial, Mastery i den ordningen) i en
   egen tråd med egen anslutning. Idag tog den otidsatta delen 37 s; parallellt blir det
   ungefär den längsta kedjan (Binary, cirka 13 s).
   **Klart:** sex familjer åt gången (`--workers`), utskriften hålls ihop per familj.
3. **Börja exakt 15:00:00.** `day.sh` sover till 15:02. Fråga i stället `list --day N
   --lane <lane>` (~1 s per anrop) från 15:00:00 tills den nya dagen syns, och starta
   sedan direkt.
   **Klart:** `day.sh` vaknar 14:59:30; `daily --wait-release` frågar Warmups varje sekund.
4. **Fortsätt efter första svepet.** Byt markeringen "dagen klar" mot en ny körning var
   15:e minut så länge dagen har olösta uppgifter. Då löser roboten själv Single Solve
   och kör loppet när någon pushar en ny lösare och driftsätter den. Tidsatta lopp får
   bara köras en gång per rutt och dag. Spara bästa tid i `hints.json`, så att varje
   körning inte förbrukar en tidsatt variant (32 för dagens Metadata-rutter, 256 för
   Warmups).
   **Klart:** cron var 15:e minut; ett nytt svep bara när `~/src` eller `hints.json`
   ändrats (`~/.huntress/dayNN.swept`). Varje rutt körs tidsatt en gång (`--rerace`
   kör om); `hints.json` sparar `races` och `best_on_clock_ms`.
5. **Web: hoppa över filhämtningen** när start-svaret har `targets[]`. Då rapporteras
   rutten som olöst i stället för som fel, och ett meningslöst anrop försvinner.
   **Klart:** ingen hämtning och ingen pipelining; `daily` startar Web bara med
   `--lane web-exploitation`, så svepen inte väcker mål i onödan.
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
   **Mätt 21 okt 00:20 (Homebase → proxyn, Binary dag 20):** Range stöds inte (svaret
   är 200 med hela filen), så uppdelad hämtning går inte. Utanför rusningen tog filen
   3,0–3,6 s (~9 MB/s), mot 8,4 s vid släppet. Datan går inte att komprimera (gzip ger
   samma storlek och 4,8 s), och roboten skickar redan `Accept-Encoding: identity`.
   Kvar att ta reda på: om servern kompenserar för storleken.
10. **Kortare utskrift.** Loggen blev 2,2 MB eftersom uppgiften skrivs ut två gånger
    (16 000 rader för Script). Skriv ut den en gång och sammanfatta när frågorna är fler
    än ~50. Hela listan finns redan i `work/<id>/assignment.json`, så kravet på full
    insyn i `AGENTS.md` uppfylls ändå.
    **Klart:** frågelistan skrivs ut en gång, med uppdraget; status före och efter
    hänvisar till den.

### P2: när P0 och P1 är klara

11. **Vilken klocka gäller?** Jämför tiden i Hall of Fame med robotens `from`/`to`
    (idag TT 285/840 ms, Mastery 820/2 712 ms). Stämmer `to` räknas serverns rättning
    på 1,9 s, och då lönar det sig att dela upp Mastery-inlämningen.
12. **Gemensam hints-källa.** `hints.json` finns på PC:n och på Homebase och glider
    isär. Den Homebase som spelar är sanningen.

## Läget 21 okt: alla dag 1–20 lösta; tiden och Hall of Fame avgör

`list` visar att laget har löst alla 6 lanes × 3 lägen för dag 1–20. Poäng för gamla
dagar finns alltså inte kvar. Kvar finns dag 21–31 och Hall of Fame (varje ny tidsatt
variant kan sänka lagets bästa tid per rutt).

Lagets sista flagga per dag, i minuter efter släppet (`scripts/homebase.sh times`):

| Dag | 15 | 16 | 17 | 18 | 19 | 20 |
| --- | --- | --- | --- | --- | --- | --- |
| Sista flagga | 52,6 | 13,6 | 83,6 | 65,0 | 49,3 | 14,9 |
| Lane | Metadata M | Metadata M | Script M | Script M | Web M | Metadata M |

- **Metadata Mastery var sist tre av sex dagar.** En ny typ löses för hand och kodas
  sedan. Körschemat i `CLAUDE.md` ("Release day: a new question type") siktar på cirka
  6 min: `homebase.sh pull`, parser, `deploy`, `sweep`. Cron varje minut tar upp ny kod
  inom 60 s.
- **Script Mastery dag 17–18 och Web Mastery dag 19:** Ilses, Parsas och Davids lösare
  bör ligga i den gemensamma roboten, så att de körs automatiskt från 15:00.
- **Hall of Fame:** `hof.sh` racear om alla bevisade Warmups- och Metadata-rutter varannan
  timme 00:30–10:30 UTC, med `--reserve 8` och `--gate-ms 250` (median 208 ms uppmätt).

## Läget 23 okt: roboten är bra på allt som redan funnits — förebygg det nya

Roboten tog **6 flaggor av 18** fram till 15:17 och stod sedan still. Resten av dagens
flaggor kom in senare på kvällen på annat sätt: svepet 19:20 UTC visar varje dag 23-rutt
som `already solved`, även Web. Dagen är alltså hel — men roboten gjorde inte jobbet, och
det är precis det vi ska förebygga. Inte en enda rutt föll på att roboten saknade
täckning: den svarade på 276 av 276 Binary-frågor och 28 av 28 Metadata-frågor. Fem andra
saker stoppade den:

| Rutt | Vad som stoppade | Kostade |
| --- | --- | --- |
| Metadata TT + Mastery | 27 av 28 frågetyper godkända; `zip.central_directory_member_names` avvisad | 2 flaggor |
| Binary S + TT + Mastery | alla 276 svar fanns; gruppen `d*_analysis_machine` (15 decimalkoder) avvisad | 3 flaggor |
| Android TT + Mastery | ny v2-asset utan payload (`codec: "analysis"`): koden räknas fram i appen | 2 flaggor |
| Script TT + Mastery | 12 typer godkända, `carrier` och `obfuscation` avvisade, 7 typer utan svar | 2 flaggor |
| Web alla tre | lanen fanns i `main` 11:57 men Homebase körde koden från 22 okt | 3 flaggor |

### Fem sätt att fastna, och vad som hindrar dem

1. **Ett fel svar i en grupp dödar hela gruppen.** En förfrågan är allt-eller-inget, så
   ett fel svar bland 15 lämnade även de 14 rätta oaccepterade — och vi såg bara "15 är
   fel". **Klart:** en avvisad frågetyp delas nu i halvor till de avvisade svaren är
   utpekade (`rejected_answer_ids`); de rätta blir godkända på vägen. Ett fel svar bland
   15 kostar nu ett svar, inte femton, och rapporten pekar på den enda fråga som ska lagas.
2. **Stavningen är graderarens val, inte bytenas.** Dag 20 ville servern ha hex i stället
   för namn, dag 22 decimal i stället för "x86", dag 23 avvisade decimal. **Klart:** en
   lösare får ange `alternatives` (andra stavningar samma bevis tillåter). De skickas
   aldrig på klockan — men när servern avvisat ett svar otidsat provar roboten dem själv,
   en förfrågan per stavning, och rapporten skriver vilken som togs. Maskinfältet i
   `solvers/binary.py` är första producenten (decimal på klockan, därefter etikett och hex).
3. **Ett lås såg ut som ett fel.** Mastery svarar 409 så länge Time Trial inte är löst.
   Roboten frågade ändå, fick "error" och `day.sh` gjorde om hela svepet tio gånger
   (12:59–13:17) innan den gav upp — och brände hela retry-budgeten som finns för riktiga
   fel. **Klart:** en rutt som inte går i mål blockerar nu lägena efter sig i familjen,
   både i det parallella och i det tidsatta (sekventiella) spåret.
4. **Rankade varianter brändes på svar vi visste var fel.** Ett lopp lämnar in en gång,
   men ingenting kom ihåg att servern just avvisat rutten: dag 23:s Metadata TT racades
   tre gånger på samma avvisade konvention (13:17, 19:20, 19:23 UTC — 524 och 510 ms på
   klockan, `incorrect`) och Android TT tre gånger utan svar alls. **Klart:** hints.json
   bär `turned_down`/`turned_down_at` och grinden hoppar över rutten; ett senare
   `recorded_at` (en lösare som gick i mål) eller en körning som slutar `complete` släpper
   märket, och `--rerace` kör ändå. Första versionen flyttade bara slöseriet ett steg —
   svepet 19:32 hoppade över båda TT men racade deras Mastery (1 249 ms, `incorrect`) —
   så en sådan skip blockerar nu lägena efter sig, precis som 409-kedjan.
5. **Ingen såg vad som var fel.** Svaret låg i en logg på 2,4 MB. **Klart:**
   `scripts/answer_gaps.py` (offline, gratis: vad roboten svarar för en sparad rutt, typ
   för typ, vilka typer den inte kan svara på, och `--show` skriver värdena) plus
   `scripts/homebase.sh gaps <id>`; `homebase.sh report` skriver nu avvisad typ, utpekade
   fel svar och typer utan svar under varje rutt.

### Kvar att göra, med ägare

- **Metadata (Darin):** undersökt 23 okt. Zippen är helt ordinär (15 poster,
  central-directory-ordning == lokal headerordning == `zipfile`:s vy, inga katalogposter)
  och vårt svar är en trogen kompakt läsning. Det enda som skiljer från tidigare dagar är
  att posterna ligger i kataloger — vilken form graderaren vill ha står inte i bytena, så
  `_orderings` i `solvers/metadata.py` erbjuder sorterade sökvägar, basnamn och sorterade
  basnamn som `alternatives`. Nästa otidsatta svep avgör saken i tre förfrågningar.
  1 fråga, 2 flaggor.
- **Binary (David):** kör svepet igen och läs vilket av de 15 maskinsvaren som pekas ut;
  `_spellings` kan redan ha lagat det själv. 1 fråga, 3 flaggor.
- **Android (Darin):** ta fram regeln ur `classes.dex` (subagenten `ctf-android`) och
  lägg den som en codec i `mobile_puzzle.py`. 1 fråga, 2 flaggor.
- **Script (Ilse):** 9 typer, störst kvarvarande arbete. `answer_gaps.py --show` på den
  sparade rutten ger både de avvisade värdena och de sju typerna utan svar.
- **Drift (Darin):** VM:n var nere 06:25–12:56 och 14:36–18:26 UTC den 23:e. Roboten
  spelar bara när den är uppe, och en pushad fix spelar bara när någon driftsätter: dag
  23:s Web-lane låg i `main` fem timmar utan att köras. Nästa steg är att `day.sh` själv
  hämtar `main`, kör testerna och byter `~/src` (samma grind som `deploy` redan har), så
  att en pushad lösare spelar inom en minut utan en människa vid tangentbordet.

### Om en releaseagent (Ilses förslag)

Rätt instinkt, och den hör hemma efter punkt 1–4: en agent som läser rapporten tre
minuter efter släppet behöver att rapporten redan pekar på den enda frågan som är fel —
annars läser den 2,4 MB logg. Med `answer_gaps.py` och delningen på plats är indatan
liten och entydig, och agenten kan hålla sig till att skriva en regel per utpekad fråga
på en egen gren, utan att starta, lämna in eller driftsätta något. Gör den läs-only mot
Game Master (`status`, `artifact`) och låt replay-grinden (`verify_fields.py`) avgöra.

## Grenen `work-in-progress` (Codex, 21 okt): inte inslagen

Provad 21 okt 14:10 på dag 20:s riktiga uppgifter (kopia på Homebase, ingen inlämning):

| Lösare | Besvarade frågor |
| --- | --- |
| Script | 456 av 1 329 (34 %, korrektheten okänd) |
| Binary | 0 av 240 |
| Android | 0 av 1 |

Ingen ger alltså en flagga, eftersom Single Solve kräver alla svar. Dessutom:

- Grenens `macho_cpu_type_set` svarar med namn (`["ARM64"]`), men servern godkände
  hex (`["0x0100000c"]`, `learn` 20 okt).
- Lås, `daily`, `fastpath`, `hints` och `day.sh` dubblerar det som redan körs på
  `release/p0`.
- Grenen tar bort `.env.example`.

Idén med ett `lanes`-attribut per lösare är bra (punkt 8) och kan tas in separat.
Script-lösaren är värd att bygga vidare på för Ilses lane, testad mot riktiga frågor
med `learn`.

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
