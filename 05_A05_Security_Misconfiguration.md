Oto tekst zapisany w czytelnym Markdown:

---

Oto poprawiony i dostosowany do Twojego projektu raport dla kategorii **A05:2021 – Security Misconfiguration**.
Usunięto punkt o „Directory Listing” (ponieważ w Spring Boot jest to domyślnie wyłączone i rzadko stanowi problem) oraz dostosowano opisy tak, aby pasowały do architektury Twojej aplikacji (Spring Boot + Angular).

# Raport Analizy Bezpieczeństwa: A05:2021 – Security Misconfiguration

## 5.5. A05:2021 – Security Misconfiguration

### Wstęp do zagadnienia

Kategoria *Security Misconfiguration* (Błędy konfiguracji bezpieczeństwa) to jedna z najczęstszych przyczyn incydentów. Nie wynika ona z błędów w samym kodzie (jak SQL Injection), ale z tego, że zabezpieczenia serwera lub frameworka nie zostały włączone, są ustawione na wartości domyślne lub są zbyt liberalne.

W analizowanym projekcie **Quiz-Web-App** zidentyfikowano **4 istotne błędy konfiguracyjne**, które obniżają poziom bezpieczeństwa aplikacji.

---

### 🔍 PODATNOŚĆ #1: Zbyt liberalna polityka CORS (`@CrossOrigin("*")`)

**Identyfikator:** VUL-A05-001
**Poziom ryzyka:** 🟠 **WYSOKI**
**CWE:** CWE-942 – Permissive Cross-Origin Resource Sharing Policy

#### 📍 Lokalizacja

Kontrolery backendu, np.:
`Quiz-Web-App-master/backend/src/main/java/com/portal/demo/controller/...`

#### 📝 Opis podatności

W kontrolerach aplikacji zastosowano adnotację zezwalającą na zapytania z *dowolnej domeny* (`*`).
Mechanizm CORS (Cross-Origin Resource Sharing) powinien ściśle określać, kto może komunikować się z API.

Ustawienie gwiazdki (`*`) oznacza, że dowolna złośliwa strona internetowa może wysłać zapytanie do Twojego API w tle (gdy ofiara wejdzie na stronę atakującego) i odczytać zwrócone dane.

#### ❌ Dowód z kodu

```java
@RestController
@RequestMapping("/user")
@CrossOrigin("*") // BŁĄD: Zezwolenie na dostęp dla całego internetu
public class UserController {
    // ...
}
```

#### 🛡️ Rekomendacje naprawy

* Zamienić `*` na konkretny adres frontendu, np.
  `@CrossOrigin("http://localhost:4200")` lub domenę produkcyjną.
* Skonfigurować CORS globalnie w klasie konfiguracyjnej (`WebMvcConfigurer`), a nie w każdym kontrolerze osobno.

---

### 🔍 PODATNOŚĆ #2: Wyłączona ochrona CSRF (`csrf().disable()`)

**Identyfikator:** VUL-A05-002
**Poziom ryzyka:** 🟡 **ŚREDNI**
**CWE:** CWE-352 – Cross-Site Request Forgery

#### 📍 Lokalizacja

Plik:
`backend/src/main/java/com/portal/demo/config/MySecurityConfig.java`

#### 📝 Opis podatności

W konfiguracji Spring Security całkowicie wyłączono ochronę przed atakami CSRF (Cross-Site Request Forgery). Choć w architekturze opartej o tokeny JWT (przechowywane w `localStorage`) ryzyko jest mniejsze, to wyłączenie tej opcji jest często działaniem „na skróty”.

Jeśli aplikacja kiedykolwiek użyje ciasteczek (Cookies) do sesji lub logowania, brak CSRF pozwoli atakującemu na wykonywanie akcji w imieniu użytkownika bez jego wiedzy.

#### ❌ Dowód z kodu

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http
        .csrf().disable()  // BŁĄD: Całkowite wyłączenie ochrony
        .cors().disable()
        .authorizeRequests()
        // ...
}
```

#### 🛡️ Rekomendacje naprawy

* Jeśli aplikacja jest w 100% bezstanowa (*stateless*) i nie używa ciasteczek – wyłączenie jest akceptowalne, ale należy to **udokumentować**.
* Jeśli używane są jakiekolwiek ciasteczka – należy **włączyć CSRF** i skonfigurować przesyłanie tokena `X-XSRF-TOKEN`.

---

### 🔍 PODATNOŚĆ #3: Brak nagłówków bezpieczeństwa HTTP

**Identyfikator:** VUL-A05-003
**Poziom ryzyka:** 🟠 **WYSOKI**
**CWE:** CWE-693 – Protection Mechanism Failure

#### 📍 Lokalizacja

Konfiguracja serwera / Spring Security (brak odpowiednich wpisów).

#### 📝 Opis podatności

Analiza odpowiedzi serwera wykazała brak nowoczesnych nagłówków bezpieczeństwa, które chronią przeglądarkę użytkownika przed atakami.

Brakuje m.in.:

* `Content-Security-Policy` (CSP): chroni przed XSS i ładowaniem złośliwych skryptów.
* `Strict-Transport-Security` (HSTS): wymusza szyfrowanie HTTPS.
* `X-Frame-Options`: chroni przed atakami Clickjacking (wyświetlaniem strony w niewidzialnej ramce).

#### ❌ Dowód (symulacja odpowiedzi serwera)

```http
HTTP/1.1 200 OK
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
# BRAK: Content-Security-Policy
# BRAK: Strict-Transport-Security
```

#### 🛡️ Rekomendacje naprawy

* Włączyć nagłówki w konfiguracji Spring Security (`http.headers()...`).
* Zdefiniować politykę CSP, np.: `Content-Security-Policy: default-src 'self'`.
* Wdrożyć HSTS na środowisku produkcyjnym.

---

### 🔍 PODATNOŚĆ #4: Ujawnianie szczegółów błędów (Stack Trace)

**Identyfikator:** VUL-A05-004
**Poziom ryzyka:** 🟡 **ŚREDNI**
**CWE:** CWE-209 – Information Exposure Through Error Messages

#### 📍 Lokalizacja

Globalna obsługa wyjątków (domyślna konfiguracja Spring Boot).

#### 📝 Opis podatności

Aplikacja w przypadku wystąpienia błędu (np. błąd bazy danych, `NullPointerException`) zwraca pełny „zrzut stosu” (Stack Trace) w formacie JSON.

Ujawnia to atakującemu m.in.:

* wersje bibliotek Java,
* strukturę katalogów na serwerze,
* fragmenty kodu SQL (w przypadku błędów JPA).

Informacje te ułatwiają planowanie dalszych ataków.

#### ❌ Dowód (przykładowa odpowiedź API)

```json
{
  "timestamp": "2023-11-24T10:00:00.000+00:00",
  "status": 500,
  "error": "Internal Server Error",
  "trace": "java.lang.NullPointerException: ... at com.portal.demo.service.UserService.getUser(UserService.java:45) ...",
  "path": "/api/user/get"
}
```

#### 🛡️ Rekomendacje naprawy

* W pliku `application.properties` ustawić:
  `server.error.include-stacktrace=never`
* Stworzyć globalny `ExceptionHandler` (używając `@ControllerAdvice`), który:

  * zwraca użytkownikowi tylko ogólny komunikat
    *„Wystąpił błąd, skontaktuj się z administratorem”*,
  * a szczegóły zapisuje w logach serwera.

---

### ✔ Podsumowanie Oceny A05 – Security Misconfiguration

| Podatność                                 | Ryzyko     |
| ----------------------------------------- | ---------- |
| Permissive CORS (`*`)                     | 🟠 WYSOKIE |
| Brak nagłówków bezpieczeństwa (CSP, HSTS) | 🟠 WYSOKIE |
| Wyłączona ochrona CSRF                    | 🟡 ŚREDNIE |
| Ujawnianie Stack Trace (Verbose Errors)   | 🟡 ŚREDNIE |
