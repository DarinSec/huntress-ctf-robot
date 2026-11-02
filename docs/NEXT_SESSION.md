# Fortsättning – Huntress CTF-roboten

Sparat den 17 oktober 2026, Europe/Stockholm. Planerad fortsättning: 18 oktober 2026.

## Mål och val

Bygga en robot som själv analyserar tilldelade Huntress CTF 2026-uppgifter, löser dem, lämnar in svar och rapporterar verkligt resultat. Single Solve, Time Trial och Mastery ska stödjas.

Användaren har valt att köra roboten på sin egen Windows-dator med en parad Game Master-token.

## Klart

- Python-klient för de dokumenterade Game Master-operationerna.
- Automatisk lösningskedja för ett valt försök med separata resultat för slutfört, delvis löst, felaktigt, utgånget och väntande poängsättning.
- Kontroller av försökets identitet, svarsfält och filens SHA-256 före inlämning. Redan accepterade Mastery-svar bevaras.
- Deterministiska lösare för uttryckliga Base64-, ROT13-, hexadecimal- och binäruppgifter samt uttryckliga JSON-svarskartor. Motstridiga svar hoppas över.
- Nedladdade filvarianter bevaras. Token maskeras i utdata och omdirigeringar blockeras.
- `doctor` hämtar schema och utmaningslista samt valfria befintliga statusar. Det startar inga försök och skickar inga svar.
- `--prompt-token` läser token dolt i terminalen utan att spara den.
- `scripts/huntress.ps1` startar roboten med tillgänglig Python och projektets källkod.
- Anslutnings- och parningsinstruktioner finns i `CONNECT.md`. Översikt och begränsningar finns i `USAGE.md`.

### Hastighet (18 oktober 2026)

dot_com löstes på 8,091 s, medan snabbaste lag klarade 0,482 s. Orsakerna var att roboten saknade Morse-/flerlagerslösare, att den gjorde 4–6 anrop efter start och att varje anrop öppnade en ny TCP+TLS-anslutning. Åtgärder:

- `client.py` återanvänder en keep-alive-anslutning. Uppmätt mot den riktiga värden: ≈ 20 ms per anrop i stället för ≈ 88 ms. `submit_many` skickar alla svar i en POST.
- `solve --timed` (`fastpath.py`): list och status körs före start. Medan klockan går körs bara start → artifact → lösning → en submit. Utskrift, sparning och tidstabell kommer efteråt.
- `decoders.py` och `LayeredDecodeSolver`: Morse, binär, hex, decimal, Base32, Base64 och ROT13/ROT47 i valfri ordning, tills texten uttryckligen anger svaret. dot_com-artefakten löses på ≈ 3 ms.
- `bench` är läs-only och jämför ny anslutning med keep-alive.

### Arbetssätt: en AI, kod per lane

- En AI bygger och analyserar. Specialiseringen ligger i kod (`src/huntress_ctf/solvers/<lane>.py`) och i playbooks, inte i separata modeller. Läs `CLAUDE.md` för det dagliga flödet: lös en gång, kodifiera, verifiera otidsatt, kör tidsatt.
- Subagenter finns bara för tunga lanes: `.claude/agents/ctf-binary.md` och `ctf-android.md` (Opus). Lätta lanes körs i huvudsessionen.
- `artifact_summary` visar filtyp och lane-tips samt UTF-16LE-strängar.
- `.venv` innehåller pefile och pyelftools (`.[analysis]`). jadx 1.5.6 ligger i `tools\jadx` med verifierad SHA-256. androguard valdes bort (≈ 35 extra paket).

### Effektivisering (18 oktober 2026, senare)

- **Buggfix:** `solve --timed` efter en slutförd otidsatt lösning använder nu `retry` med `run_for_time`, eftersom `start` bara återansluter. Den startar aldrig när poängsättning väntar, när ett otidsatt försök är aktivt eller när inga nya tidsatta varianter finns kvar.
- **Bevisade lösare (`.huntress/hints.json`):** sparas efter CORRECT. Ett tidsatt lopp kör dem först, och lösningen tar 0,22 ms i stället för 1,1 ms. `daily --timed` tävlar bara med bevisade.
- **På klockan:** uppvärmning före start och GC pausad under loppet. Mot lokal låtsasserver: 1,1 ms från start-svar till submit-svar.
- **Ny förmåga:** uppackning i minnet (ZIP/ZipCrypto med `infected`, gzip, tar), metadata (EXIF/GPS, PNG, PDF, Office), IOC:er och avkodning av PowerShell-, Base64- och char-blobbar, samt `FactSolver` för frågor av typen "vad är författaren/URL:en/IP:n?".
- **AI-flöde:** `daily` kör allt i ett svep. Olösta uppgifter får `work/<id>/triage.md`. `triage <fil>` fungerar offline. Lösare registreras automatiskt, så det räcker med en ny fil i `solvers/`.
- `.claude/settings.json` släpper igenom tester och läs-only-kommandon utan fråga.
- **Väntar på användaren:** `.env` med token (instruktion i `.env.example`). Därefter körs `bench` och `doctor` live och schemat läses för att se om en rundresa kan sparas.

### Hastighet, del 2 (19 oktober 2026)

Mätt lokalt med syntetiska filer. Lösningssteget på klockan, före och efter:

| Fall | Före | Efter | Åtgärd |
| --- | --- | --- | --- |
| ZipCrypto-ZIP på 1 MB (`infected`) | 910 ms | 44 ms | `tar.exe`/7-Zip/unzip i stället för stdlib (ren Python, 1,1 MB/s). CRC-kontroll per post. AES-ZIP fungerar nu också (40 ms). |
| Skript på 200 KB, fråga om URL | 210 ms | 15 ms | `peel` 137 → 5 ms (C-snabb textkontroll, cache, `translate`), `FactSolver` kör bara den IOC-typ som frågan gäller |
| Binär på 2 MB | 299 ms | 78 ms | Utrullad UTF-16-strängregex (3 gånger snabbare), förfilter för `[char]`/`FromBase64String` |
| kernel32.dll (836 KB) | – | 33 ms | samma |

Nätverk och flöde:

- **En motor:** otidsatt `solve`/`daily` kör samma väg som loppet (`run_fast`): list, start, artifact och en `submit_many`. Tidigare krävdes 6–8 anrop med status före varje svar. `daily` hämtar inte längre listan en gång per uppgift.
- **Pipelining:** `bench --pipeline` testar status- och artifact-GET i samma sändning och sparar resultatet i `.huntress/network.json`. Pipelining slås bara på om svaren kommer i rätt ordning och paret blir snabbare. Fel eller ej verifierbar hash ger vanlig GET och stänger av pipelining för vägen.
- **Välj väg:** `bench --compare` mäter direkt HTTPS och Homebase-proxyn och rekommenderar den snabbaste.
- **`triage <fil> --time`:** offline-mätning per lösare.
- Bitdefender satte en temporär kommandoutdata i karantän eftersom den citerade IOC-testfixturer. Det var ett falsklarm, men riktiga prov i `artifacts/` och `work/` kan också hamna i karantän.

Livemätning från spelarens PC i Sverige (19 oktober 2026, `bench --compare --pipeline --challenge warmups-day-01`):

- TCP-rundresa till Cloudflare (nod GOT): 19 ms. Ett anrop utan token får 401 på 12 ms.
- Med token: status ~690 ms (median, keep-alive) och artifact ~840 ms för 148 byte. En ny anslutning kostar bara ~65 ms mer. Tiden går alltså bakom Cloudflare (ursprungsservern och medlemskontrollen), inte i vår kod eller i nätet hit.
- Pipelining fungerar på den direkta vägen men är långsammare: paret tar 1 559 ms mot 1 456 ms för två vanliga anrop, i en andra mätning 266 ms långsammare. Servern behandlar anropen ett i taget, så pipelining sparar bara nätverkets rundresa (~19 ms) och förlorar mer än så. Den är avstängd (`false`). Den första proben föll av en annan orsak: den började med `list` utan dag, som tar 80 s, och gick i timeout.
- `list`: ~1 s för en dag och lane, 4,2 s för en dag, **80 s för allt (296 poster)**. `solve <id>` hämtade tidigare hela listan och gick i timeout efter 30 s. Nu läses dag och lane ur ID:t (`lookup_challenge`), `list` har 180 s timeout, och otidsatt `daily` hoppar över uppgifter som är markerade som lösta.
- Schemat i live-svaren: `accepted_ids` (inte `accepted_answer_ids`), `artifacts[0].sha256` (stämmer med `op=artifact`-bytena) och `questions[{id, question, answer_format}]`. Parsern läser nu båda varianterna. Homebase-proxyn går inte att nå från PC:n, inte ens via VPN; använd Homebase-terminalen.
- Alla 16 uppgifter på dag 1 är redan lösta i alla lägen; Read the Rules lämnas in via CourseStack. Bara Metadata Forensics `/time_trial` och `/mastery` har `run_for_time_supported: true`, så på övriga tidsatta rutter är en vanlig start tidsatt. Listan har sex lanes, inklusive Web Exploitation med live-mål i `targets[]` och ingen artefakt, samt fälten `ranked_deadline_ms`, `ranked_solve_budget_ms` och `ranked_transfer_allowance_ms`.
- Homebase (proxyn, `bench --challenge warmups-day-01`, Python 3.12.3): status ~347 ms och artifact ~335 ms (median, keep-alive), ungefär dubbelt så snabbt som från PC:n. **Tidsatta lopp körs därför från Homebase.** Koden kopieras dit med `scp -r .\src HuntressCTF@<homebase-ip>:~/` över CTF-VPN:en; IP:n fås med `hostname -I`, och 10.1.0.0/16 går genom VPN:en. Tillstånd sparas i `~/.huntress/` på Homebase.
- **Läge 19 oktober (dag 19):** alla 295 lösbara uppgifter för dag 1–19 är lösta. Kvar är bara Read the Rules, som lämnas in i CourseStack. Dag 19 har 24 uppgifter, inklusive Web Exploitation. Nya uppgifter släpps 09:00 ET (15:00 svensk tid). Det som återstår är nya dagar och Hall of Fame-tider via tidsatt `retry`. Observera att `daily --timed` i dag bara tävlar på rutter med `run_for_time_supported` och en bevisad lösare; äldre, alltid tidsatta rutter tas inte med.
- Verifierat live: `solve warmups-day-01` (redan löst) ger exit 0 på 6 s; start-anropet tog 2,1 s.

### Inlärning på gamla övningar (19 oktober 2026, kväll)

- Läs-only-genomgång av alla 296 uppgifter: script-analysis har 73 171 frågor, binary 11 665, metadata 923, warmups 950 och android 109. Före arbetet svarade roboten på 17 warmups-frågor; 0 metadata, 16 binary och 7 script.
- **Warmups klar:** ny lösare `warmup-blobs` med kursen dag 1–19 (`CURRICULUM`), nya avkodare och stöd för separata leveranser, som hämtas parallellt (28 st på ~3–5 s i stället för ~20 s). Offline klaras 950/950 frågor. **Live: 34 tidsatta rutter CORRECT** (Mastery upp till 93 svar i ett anrop). Dag 12 och 18 TT/Mastery har 0 varianter kvar och startades inte.
- Spelaren har godkänt att retry, även tidsatt, får förbruka varianter för att få facit.
- `.huntress/hints.json` på PC:n har 34 bevisade lösare. Kopiera den till Homebase (`scp .huntress\hints.json HuntressCTF@<homebase-ip>:~/.huntress/`) innan `daily --timed --lane warmups` körs där.
- Bitdefender: börja med lanes vars prover inte liknar skadekod (metadata, android); script och binary väntar på spelarens beslut.
- **Vad som räknas på klockan** (NTP-korrigerat; PC:ns klocka gick 5,07 s före): serverns `started_at` sätts i slutet av start-anropet. De ~2,8 s förberedelse räknas alltså inte. Därefter räknas: start-svaret (~120 ms), nedladdningen (~1 s från PC:n), lösningen (0,3–30 ms) och submit (~1,8–1,9 s från PC:n). Från PC:n blir det 1,1–3,0 s på klockan. `seconds` i `daily` är hela körningen, inte lopptiden. Roboten skriver nu ut `timings_ms.server_clock_ms {from, to}` för varje tidsatt lopp.
- Homebase-lopp: 0,71–2,0 s och 3,58–4,82 s på serverklockan minuter isär. Det är serverns varians; lösningen tog 0,3 ms båda gångerna. En andra AI bedömde att klockan nästan säkert stoppas när submit *kommer in*, så `from` är den rimliga lopptiden. API:t har ingen Hall of Fame-operation och inga tidsfält (`x-huntress-auth-version: oidc-v1` tyder på en inloggningskontroll per anrop).
- Nytt: säkrad nedladdning på två anslutningar, lastgrind (`--gate-ms`, `--gate-wait`), `--repeat N` och `server_clock_ms.start_tail`. Live från PC:n: grinden fungerade och två lopp gav 1 157 och 1 126 ms. Förslag på Homebase: `python3 -m huntress_ctf solve warmups-day-13/time_trial --timed --repeat 5 --gate-ms 400`.
- **Homebase via SSH-nyckel** (`~/.ssh/huntress_homebase`, `HuntressCTF@<homebase-ip>`): AI:n kan driftsätta (`tar | ssh`) och köra själv. Icke-interaktiv ssh läser inte `.bashrc`, så sätt `PYTHONPATH=~/src HUNTRESS_GM_URL=http://10.0.0.219/huntress-ctf-proxy` i kommandot.
- Homebase-lopp kl. ~22 (svensk tid, servern seg): `start_tail` ~148 ms (samma som från PC:n, alltså serverns eget arbete efter `started_at`), nedladdning 486–878 ms, **bästa tid på klockan 633 ms**. Med en lugn server (nedladdning ~0,33 s) blir golvet ≈ 0,15 + 0,33 ≈ 0,48 s, samma som topplaget. Via proxyn: länknedladdning 468 ms mot 533 ms för `op=artifact` (median), och status listar länkar. Grinden på 400 ms stoppade loppen när status låg på 0,5–1,6 s, utan att förbruka varianter.
- **Metadata Forensics klar (19 oktober, sent):** lösaren `metadata-facts` besvarar 947/947 gamla frågor. Konventionerna är bekräftade av servern via inlärningskörningar per frågetyp; se `CLAUDE.md`. 33 rutter är CORRECT live från Homebase, med 0,65–1,8 s på klockan. Homebase har nu 67 bevisade lösare (34 warmups, 33 metadata) i `~/.huntress/hints.json`. PC:ns hints-fil har bara warmups.
- Ett Mastery-anrop godtas bara om alla svar i det är rätt. Nytt kommando: `learn <id>` skickar svaren per frågetyp och visar vilka typer som avvisas (förbrukar en variant).
- Dag 1 Metadata TT/Mastery ger HTTP 409 `legacy_attempt_pinned` vid tidsatt retry (ett gammalt försök från 1 oktober är fastlåst). Fråga arrangörerna. Felmeddelanden visar nu serverns orsak.
- Nedladdning via start-svarets länk (`download`/`sha256` på toppnivå) är ~200 ms snabbare än `op=artifact`. Leveranser hämtas med `op=artifact&delivery=<index>`, som också fungerar via proxyn. Mastery dag 1–6 misslyckades på Homebase för att proxyn inte listar några länkar; det är åtgärdat och verifierat på PC:n.
- Proben på Homebase-proxyn föll av samma `list`-timeout. Kör om den med ny kod (`scp` igen). Vinsten blir i bästa fall en nätverksrundresa på några ms, eftersom servern behandlar anropen i tur och ordning.

### Dag 20 (20 oktober 2026)

- Cron-skriptet `day.sh` på Homebase ligger nu i repot som `scripts/homebase-day.sh`. Warmups dag 20 gick på **285 ms** i Time Trial och 820 ms i Mastery. Metadata (Mach-O `macho.cpu_type_set`), Script (1 329 frågor), Binary (240 frågor, 33 MB) och Android är olösta: lösare saknas.
- En robot som startats för hand och cron-körningen gick samtidigt från 15:01:50. Laget delar försök, så bara en robot får spela.
- Lagets prioriteringar och uppdelning per lane: **`PLAN.md`**.

Senaste testkörningen: **159 tester passerade** (20 oktober 2026). Tidigare: 132 tester passerade med Python 3.12 i `.venv`. Testerna använder syntetiska data, mockade API-svar och en lokal HTTP-server för keep-alive- och pipelining-testerna.

## Nästa steg

1. Om användaren saknar en parad token: följ den vanliga parningen via autentiserad Homebase enligt `CONNECT.md`. En befintlig förlorad token kan inte återhämtas med vanlig parning; återställning kräver ett separat uttryckligt val.
2. Kör följande i en lokal interaktiv PowerShell-terminal från projektmappen:

   ```powershell
   .\scripts\huntress.ps1 --base-url https://2026.huntress.ctf.games --prompt-token doctor --output integration-data
   ```

3. Ange token endast vid den dolda terminalprompten. Klistra inte in token i chatten.
4. Läs den nya rapporten och de verkliga API-svaren under `integration-data/capture-.../`. Anpassa klienten till eventuella skillnader i API-strukturen.
5. Hämta status för verkliga tillgängliga utmanings-ID:n i de tre lägena med upprepade `--challenge ID`, utan att starta nya försök för att skapa exempel.
6. Bygg därefter fler uppgiftsspecifika lösare utifrån verkliga tilldelade filer och fullständiga offentliga instruktioner.
7. Kör `bench --compare --pipeline --challenge <id>` med token (läs-only). Det visar den snabbaste vägen och om pipelining är godkänt. Om autentiserade anrop tar över cirka 150 ms: kör från Homebase-proxyn eller en moln-VM och kör tidsatta lopp därifrån.
8. Kontrollera att `solve <id>` löser en vanlig variant innan en tidsatt variant läggs på `solve <id> --timed`. Den otidsatta körningen använder nu samma motor som loppet.
9. Jämför `timings_ms.start_sent_to_submit_response` för ett tidsatt lopp med och utan `--no-pipeline`.

## Återstår att verifiera

- Riktigt API-schema och verkliga svar har ännu inte verifierats. Ingen token fanns i den agentsession som kontrollerades.
- Den lokala kontrollen utan token avslutades med ett tydligt autentiseringsfel och sparade endast en felrapport. Den rapporten visar inte en lyckad liveanslutning.
- Start, filhämtning, svarsinlämning och CourseStack-poäng behöver senare verifieras mot tjänsten.
- Robotens nuvarande lösare klarar ännu inte godtyckliga CTF-uppgifter eller hela tävlingen automatiskt.

## VPN och försök

Med parad token behövs inte VPN för Game Master via HTTPS: utmaningslista, filhämtning och svarsinlämning. Vissa privata tävlingsmål kan däremot kräva att datorn som kör roboten är VPN-ansluten, vanligtvis via OpenVPN. Roboten ersätter inte VPN.

Använd inte `--timed` utan ett valt tidsatt mål. Återanslut till aktuellt försök; byt inte variant automatiskt. CourseStack är den officiella poängliggaren.

## Lokalt sparläge

Arbetet ligger sparat i projektets filer. Vid kontrollen fanns ännu inga Git-commits och projektfilerna var ospårade; ingen commit skapades för denna överlämning. Privata filer och integrationsfångster ligger i ignorerade kataloger.
