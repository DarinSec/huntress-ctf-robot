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

Senaste testkörningen: **60 tester passerade** med den tillgängliga Python 3.12-miljön. PowerShell-startaren och hjälpen för `doctor` kontrollerades också. Testerna använde syntetiska data och mockade API-svar.

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
