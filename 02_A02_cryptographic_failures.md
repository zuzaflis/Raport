# A02:2021 - Cryptographic Failures

### 5.2. A02:2021 – Cryptographic Failures

#### 📚 Wyjaśnienie Zagadnienia

Kategoria **Cryptographic Failures** obejmuje podatności wynikające z niewłaściwej ochrony danych wrażliwych. W praktyce programistycznej błędy te rzadko polegają na słabości samych algorytmów, a na ich niepoprawnej implementacji, użyciu domyślnych kluczy lub całkowitym braku szyfrowania.

W analizowanym projekcie `Quiz-Web-App` zidentyfikowano **4 podatności** tej klasy, które w środowisku produkcyjnym doprowadziłyby do krytycznego wycieku danych lub całkowitego przejęcia systemu.


#### 🔍 PODATNOŚĆ #1: Hardcoded poświadczenia MySQL w `docker-compose.yml`

**Identyfikator:** `VUL-A02-001`
**Poziom ryzyka:** 🔴 **KRYTYCZNY**
**CWE:** CWE-798: Use of Hard-coded Credentials
**CVSS v4.0:** 9.3 (Critical)
**Wektor:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H`

##### 📍 Lokalizacja
**Plik:** `Quiz-Web-App-master/docker-compose.yml`

##### 📝 Opis Podatności
W pliku konfiguracyjnym `docker-compose.yml` zdefiniowano zmienne środowiskowe zawierające hasło użytkownika `root` w formie jawnego tekstu. Ponieważ plik ten jest częścią repozytorium kodu, każdy posiadający do niego dostęp automatycznie poznaje hasło administracyjne do bazy danych. Dodatkowo, konfiguracja mapuje wewnętrzny port bazy danych na port hosta (`3307`), co wystawia bazę na zewnątrz.

**Konsekwencje:**
- **Całkowite przejęcie bazy danych** przez osoby nieupoważnione.
- **Kradzież wszystkich danych** zgromadzonych w systemie (dane osobowe, wyniki quizów).
- **Możliwość zniszczenia danych** (DROP DATABASE) lub ataku ransomware.
- **Brak rozliczalności działań** – wszyscy logują się jako `root`, więc nie można ustalić sprawcy zmian.

##### 💻 Kod Podatny

```yaml
environment:
  # ❌ Hasło wpisane na sztywno w konfiguracji
  MYSQL_ROOT_PASSWORD: "bardzo_silne_haslo_123"
  MYSQL_DATABASE: "quiz_db"

ports:
  # ❌ Ekspozycja bazy danych na zewnątrz kontenera
  - "3307:3306"
````

##### ⚠️ Wpływ Biznesowy

  - **Poufność:** 🔴 **KRYTYCZNA** – Bezpośredni dostęp do wszystkich rekordów w bazie.
  - **Integralność:** 🔴 **KRYTYCZNA** – Możliwość dowolnej manipulacji danymi bez śladu.
  - **Dostępność:** 🔴 **KRYTYCZNA** – Ryzyko całkowitego usunięcia bazy danych.

##### 🛡️ Rekomendacje Naprawy

1.  **Usunięcie haseł z plików repozytorium.** Hasła należy przenieść do pliku `.env`, który zostanie dodany do `.gitignore`.
2.  **Użycie zmiennych środowiskowych.** W pliku docker-compose należy odwoływać się do zmiennych, np. `${MYSQL_ROOT_PASSWORD}`.


#### 🔍 PODATNOŚĆ \#2: Hardcoded JWT Secret w kodzie backendu

**Identyfikator:** `VUL-A02-002`
**Poziom ryzyka:** 🔴 **KRYTYCZNY**
**CWE:** CWE-321: Use of Hard-coded Cryptographic Key
**CVSS v4.0:** 9.3 (Critical)
**Wektor:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H`

##### 📍 Lokalizacja

**Plik:** `Quiz-Web-App-master/backend/src/main/java/com/portal/demo/config/JwtService.java`

##### 📝 Opis Podatności

Klucz kryptograficzny służący do podpisywania tokenów JWT (JSON Web Token) został zadeklarowany jako stała tekstowa w kodzie źródłowym Java. Bezpieczeństwo całego mechanizmu autoryzacji opiera się na tajności tego klucza. Jego ujawnienie pozwala atakującemu na generowanie własnych, poprawnych tokenów.

**Konsekwencje:**

  - **Fałszowanie tożsamości** – atakujący może stworzyć token dla dowolnego użytkownika.
  - **Eskalacja uprawnień** – możliwość wygenerowania tokenu z rolą `ADMIN` bez znajomości hasła administratora.
  - **Obejście mechanizmów autoryzacji** – pełny dostęp do wszystkich endpointów API.
  - **Trwały dostęp** – nawet po zmianie hasła użytkownika, sfałszowany token może pozostać ważny.

##### 💻 Kod Podatny

```java
// ❌ Statyczny klucz w kodzie źródłowym dostępny dla każdego
    private final static  String secretKey ="20e77bab9dcfb08fa1045a87cf1aefd05f43761b5d4bca7dae3adf22b09ce8710e31abcbca81786886143b960b330cb9f24ad24de7583e96ec118f727eb9bd1c";


private Key getSigningKey() {
    byte[] keyBytes = Decoders.BASE64.decode(secretKey);
    return Keys.hmacShaKeyFor(keyBytes);
}
```

##### ⚠️ Wpływ Biznesowy

  - **Poufność:** 🔴 **KRYTYCZNA** – Dostęp do danych każdego użytkownika.
  - **Integralność:** 🔴 **KRYTYCZNA** – Możliwość wykonywania operacji administracyjnych przez osoby nieuprawnione.
  - **Dostępność:** 🔴 **KRYTYCZNA** – Możliwość zablokowania lub usunięcia kont użytkowników.

##### 🛡️ Rekomendacje Naprawy

1.  **Rotacja klucza.** Natychmiast wygenerować nowy, silny klucz kryptograficzny.
2.  **Unieważnienie tokenów.** Wszystkie tokeny podpisane starym kluczem muszą zostać uznane za nieważne.


#### 🔍 PODATNOŚĆ \#3: Brak szyfrowania danych w tranzycie (HTTP)

**Identyfikator:** `VUL-A02-003`
**Poziom ryzyka:** 🟠 **WYSOKI**
**CWE:** CWE-319: Cleartext Transmission of Sensitive Information
**CVSS v4.0:** 7.1 (High)
**Wektor:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N`

##### 📍 Lokalizacja

**Plik:** `Quiz-Web-App-master/frontend/src/app/_services/auth.service.ts`

##### 📝 Opis Podatności

Frontend aplikacji komunikuje się z API backendowym przy użyciu nieszyfrowanego protokołu HTTP. Oznacza to, że wszystkie dane przesyłane między przeglądarką klienta a serwerem są przesyłane jawnym tekstem (plaintext).

**Konsekwencje:**

  - **Przechwycenie danych logowania** – loginy i hasła są widoczne dla każdego nasłuchującego w sieci (np. w otwartym Wi-Fi).
  - **Kradzież sesji (Session Hijacking)** – przechwycenie tokenów JWT pozwala na przejęcie konta ofiary.
  - **Manipulacja danymi** – możliwość ataku Man-in-the-Middle (MITM) i modyfikacji treści przesyłanych do serwera (np. odpowiedzi w quizie).

##### 💻 Kod Podatny

```typescript
// ❌ Adres API zdefiniowany z użyciem nieszyfrowanego protokołu HTTP
const AUTH_API = 'http://localhost:8080/api/v1/auth/';
```

##### ⚠️ Wpływ Biznesowy

  - **Poufność:** 🔴 **KRYTYCZNA** – Wyciek danych uwierzytelniających.
  - **Integralność:** 🟠 **WYSOKA** – Możliwość wstrzyknięcia fałszywych danych w locie.
  - **Dostępność:** 🟡 **ŚREDNIA** – Podatność na ataki typu DoS lub przekierowania.

##### 🛡️ Rekomendacje Naprawy

1.  **Wdrożenie TLS/SSL.** Skonfigurować certyfikat na serwerze i wymusić komunikację wyłącznie przez HTTPS.
2.  **Aktualizacja adresu.** Zmienić adresy bazowe w kodzie frontendu na `https://`.
3.  **HSTS.** Wdrożyć nagłówek HTTP Strict Transport Security, aby zapobiec atakom SSL Stripping.


#### 🔍 PODATNOŚĆ \#4: Wrażliwy dump SQL w repozytorium

**Identyfikator:** `VUL-A02-004`
**Poziom ryzyka:** 🟠 **WYSOKI**
**CWE:** CWE-200: Exposure of Sensitive Information
**CVSS v4.0:** 6.9 (Medium)
**Wektor:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:L/SI:N/SA:N`

##### 📍 Lokalizacja

**Plik:** `Quiz-Web-App-master/exam_portal.sql`

##### 📝 Opis Podatności

W repozytorium kodu znajduje się pełny zrzut bazy danych (plik `.sql`). Plik ten ujawnia szczegółową strukturę systemu, nazwy tabel i kolumn, a potencjalnie również dane testowe lub produkcyjne pozostawione przez deweloperów.

**Konsekwencje:**

  - **Ułatwienie ataków SQL Injection** – atakujący zna dokładny schemat bazy, co drastycznie przyspiesza przygotowanie skutecznych exploitów.
  - **Wyciek danych historycznych** – ryzyko ujawnienia haseł deweloperów, danych testowych lub konfiguracji zaszytych w rekordach bazy.
  - **Klonowanie systemu** – możliwość łatwego postawienia identycznej kopii systemu w celu poszukiwania innych podatności w środowisku lokalnym.

##### 💻 Kod Podatny

```sql
-- ❌ Ujawnienie struktury wrażliwej tabeli użytkowników
CREATE TABLE `users` (
  `u_id` bigint NOT NULL,
  `username` varchar(255) DEFAULT NULL,
  `password` varchar(255) DEFAULT NULL,
  ...
);
```

##### ⚠️ Wpływ Biznesowy

  - **Poufność:** 🟠 **WYSOKA** – Ujawnienie architektury informacji i potencjalnych danych.
  - **Integralność:** 🔵 **NISKA** – Pośredni wpływ na ułatwienie innych ataków.
  - **Dostępność:** 🔵 **NISKA** – Brak bezpośredniego wpływu.

##### 🛡️ Rekomendacje Naprawy

1.  **Usunięcie pliku.** Natychmiast usunąć plik `exam_portal.sql` z repozytorium.
2.  **Czyszczenie historii Gita.** Użyć narzędzi typu BFG Repo-Cleaner lub `git filter-repo`, aby trwale usunąć ślady pliku z historii zmian.
3.  **Narzędzia migracyjne.** Do zarządzania schematem bazy używać narzędzi takich jak Flyway lub Liquibase, które przechowują definicje zmian, a nie zrzuty danych.

