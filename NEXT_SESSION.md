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
- Anslutnings- och parningsinstruktioner finns i `CONNECT.md`. Översikt och begränsningar finns i `README.md`.

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

Senaste testkörningen: **118 tester passerade** med Python 3.12, både systemets Python och `.venv`. Testerna använder syntetiska data, mockade API-svar och en lokal HTTP-server för keep-alive-testerna.

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
7. Kör `bench --count 10` med token. Om autentiserade anrop tar över cirka 150 ms: mät från Homebase-proxyn eller en moln-VM och kör tidsatta lopp därifrån.
8. Kontrollera att `solve <id>` löser en vanlig variant innan en tidsatt variant läggs på `solve <id> --timed`.

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
