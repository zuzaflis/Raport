# Raport Analizy Bezpieczeństwa: A08:2021 – Software and Data Integrity Failures

## 5.8. A08:2021 – Software and Data Integrity Failures

### Wstęp do zagadnienia

Kategoria **Software and Data Integrity Failures** (Błędy integralności oprogramowania i danych) obejmuje sytuacje, w których system uruchamia kod lub korzysta z komponentów zewnętrznych (np. obrazów Docker, skryptów, paczek) bez weryfikacji ich integralności i pochodzenia.

W projekcie **Quiz-Web-App** proces uruchamiania środowiska opiera się na pliku `docker-compose.yml`, który wskazuje obrazy Docker z rejestru zewnętrznego. Na tej podstawie zidentyfikowano **podatność związaną z brakiem kontroli integralności obrazów**.

---

### 🔍 PODATNOŚĆ: Zaufanie do zewnętrznych obrazów Docker bez weryfikacji integralności

**Identyfikator:** `VUL-A08-001`
**Poziom ryzyka:** 🟠 **WYSOKI**
**CWE:** CWE-829 – Inclusion of Functionality from Untrusted Control Sphere

#### 📍 Lokalizacja

**Plik:**

* `docker-compose.yml`

**Fragment konfiguracji usług:**

```yaml
services:
  mysql-db:
    image: mysql:8.0

  # 2. Backend Spring Boot
  backend-api:
    image: zuza2828/quiz-backend:latest
    container_name: quiz-backend-api
    ports:
      - "8080:8080"
    environment:
      SPRING_DATASOURCE_URL: "jdbc:mysql://mysql-db:3306/quiz_db"
      SPRING_DATASOURCE_USERNAME: "root"
      SPRING_DATASOURCE_PASSWORD: "bardzo_silne_haslo_123"
      SPRING_JPA_HIBERNATE_DDL_AUTO: "update"
    depends_on:
      - mysql-db

  # 3. Frontend Angular / Nginx
  frontend-app:
    image: zuza2828/quiz-frontend:latest
    container_name: quiz-frontend-app
    ports:
      - "4200:80"
    depends_on:
      - backend-api
```

#### 📝 Opis podatności

Środowisko aplikacji jest uruchamiane na podstawie obrazów Docker wskazanych wyłącznie po **tagach**:

* `mysql:8.0`,
* `zuza2828/quiz-backend:latest`,
* `zuza2828/quiz-frontend:latest`.

Na poziomie konfiguracji:

* obrazy nie są przypięte do konkretnych digestów (`@sha256:<hash>`),
* brak mechanizmów weryfikacji integralności (podpisy obrazów, polityki zaufania w rejestrze),
* użycie tagu `latest` dla backendu i frontendu powoduje, że w różnych momentach może zostać pobrana inna wersja obrazu pod tym samym tagiem.

W efekcie:

* środowisko automatycznie uruchamia najnowszą wersję obrazów dostępnych pod wskazanymi tagami,
* każda zmiana obrazu w rejestrze (legalna aktualizacja lub złośliwa podmiana) jest od razu przenoszona do środowiska przy kolejnym `docker compose pull` / `docker compose up -d`, bez dodatkowej kontroli.

#### 💥 Proof of Concept

**Scenariusz:** uruchomienie zmodyfikowanego (złośliwego) backendu bez zmian w `docker-compose.yml`.

1. Do rejestru Docker publikowana jest nowa wersja obrazu:

   * pod tym samym tagiem `zuza2828/quiz-backend:latest`,
   * z dodatkowym kodem, np. nasłuchującym dane z bazy i wysyłającym je na zewnętrzny serwer.

2. Administrator aktualizuje środowisko poleceniami:

   ```bash
   docker compose pull
   docker compose up -d
   ```

3. Docker pobiera aktualny obraz `zuza2828/quiz-backend:latest` z rejestru.

4. Kontener `backend-api` startuje z nową, zmodyfikowaną wersją:

   * ma dostęp do danych logowania do bazy (`SPRING_DATASOURCE_USERNAME`, `SPRING_DATASOURCE_PASSWORD`),
   * komunikuje się z bazą `quiz_db`,
   * obsługuje żądania z frontendu.

5. Ponieważ konfiguracja nie zawiera przypięcia do konkretnego digestu ani mechanizmów weryfikacji, uruchomiony zostaje nowy obraz, mimo że plik `docker-compose.yml` się nie zmienił.

#### ⚠️ Wpływ biznesowy

* **Poufność:**

  * zmodyfikowany obraz backendu może wykradać dane z bazy (użytkownicy, wyniki, pytania, dane osobowe) i wysyłać je poza organizację;
* **Integralność:**

  * złośliwy backend może modyfikować dane (np. wyniki testów, konta użytkowników) w sposób trudny do wykrycia;
* **Dostępność:**

  * dodatkowe, niepożądane procesy (np. kopanie kryptowalut, intensywne logowanie, skanowanie) mogą obciążać serwer i obniżać dostępność aplikacji.

**Konsekwencje dla organizacji:**

* ryzyko wycieku danych oraz naruszenia przepisów o ochronie danych,
* utrata zaufania do systemu (brak pewności, jaka wersja kodu faktycznie działa w środowisku),
* potencjalne koszty związane z obsługą incydentu, analizą i przywracaniem zaufanego środowiska.

#### 🛡️ Rekomendacje naprawy

1. **Przypięcie obrazów do digestów**

   * w `docker-compose.yml` stosować referencje typu:

     ```yaml
     image: zuza2828/quiz-backend@sha256:<konkretny_hash>
     ```

   * digest powinien odpowiadać obrazowi zbudowanemu i przetestowanemu w zaufanym pipeline CI/CD.

2. **Kontrolowany proces budowania obrazów**

   * obrazy backendu i frontendu budować z kodu źródłowego w wewnętrznym procesie CI,
   * utrzymywać historię wersji i zmiany obrazów powiązane z konkretnymi commitami w repozytorium.

3. **Unikanie tagu `latest`**

   * stosować wersjonowanie semantyczne (np. `quiz-backend:1.0.0`, `quiz-frontend:1.0.0`),
   * zmiany wersji przeprowadzać poprzez świadomą modyfikację `docker-compose.yml` i proces release’owy.

4. **Dalsze wzmocnienia**

   * rozważyć wdrożenie podpisywania obrazów (np. cosign) i weryfikacji podpisów w środowisku uruchomieniowym,
   * okresowo skanować obrazy pod kątem znanych podatności.

---

### ✔ Podsumowanie Oceny A08 – Software and Data Integrity Failures

| Podatność                                                             | Ryzyko     |
| --------------------------------------------------------------------- | ---------- |
| Zaufanie do zewnętrznych obrazów Docker bez weryfikacji integralności | 🟠 WYSOKIE |
