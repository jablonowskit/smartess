SmartESS — lekki klient w Pythonie do odczytu i zapisu rejestrów Modbus z dataloggera SmartESS/Dessmonitor. Obsługuje tunelowanie Modbus RTU przez Modbus TCP (protokół specyficzny dla urządzenia) i zwraca wynik jako JSON.

Wymagania

- Python 3.7+
- Pliki `smartess_client.py` i `smartess_protocol.py` w tym samym katalogu lub dostępne w `PYTHONPATH`.

Opis
Skrypt `smartess_client.py`:

- wysyła UDP notify do dataloggera (port domyślny 58899),
- czeka na połączenie TCP od dataloggera (port domyślny 502),
- tuneluje żądanie Modbus RTU przez protokół Modbus TCP i parsuje odpowiedź,
- obsługuje odczyt rejestrów (funkcja 3) oraz zapis wielu rejestrów (funkcja 0x10),
- pozwala użyć pojedynczego wywołania CLI albo utrzymywanej sesji TCP przez `SmartESSSession`,
- zwraca wynik jako JSON z timestampem.

Nowe funkcjonalności w wersji 1.1.1:

- zapis wielu rejestrów z CLI przez `--set`,
- osobny moduł `smartess_protocol.py` z niskopoziomową obsługą protokołu,
- utrzymywana sesja TCP przez `SmartESSSession` i `smartess_open_session(...)`,
- opcjonalne użycie istniejącej sesji w `smartess_read(...)` i `smartess_write(...)`,
- obsługa wartości dziesiętnych i heksadecymalnych w `--set`.

Różnica względem Modbus

- **Modbus TCP**: MBAP (TID, PID, Length, Unit ID) + PDU (funkcja + dane), bez CRC; Unit ID w MBAP służy jako adres slave.
- **Modbus RTU**: ramka serialowa: Unit ID + PDU + CRC16 (2 bajty, little-endian).
- **SmartESS (tunel)**: używa MBAP, ale PDU ma prefiks `0x04 0x01` i zawiera **RTU PDU + CRC** — CRC RTU jest zachowany wewnątrz tunelu. Oznacza to, że nie można traktować tego ruchu jak zwykły Modbus TCP: trzeba obsłużyć prefiks tunelowania oraz obliczać/weryfikować CRC RTU.

Użycie
python smartess_client.py <IP_DATALOGGERA> <REGISTER> [--count N] [--localip X.X.X.X] [--tcp-port 502] [--udp-port 58899] [--debug]
python smartess_client.py <IP_DATALOGGERA> <REGISTER> --set "100,200" [--localip X.X.X.X] [--tcp-port 502] [--udp-port 58899] [--debug]

Przykłady
python smartess_client.py 192.168.1.50 100 --count 2
python smartess_client.py 192.168.1.50 326 --set "230,250"

Wyjście przykładowe:
{"ts":"2025-09-30T12:00:00","100":123,"101":-5}
{"ts":"2025-09-30T12:00:05","written_base":326,"written_qty":2,"values":[230,250]}

Argumenty

- `IP_DATALOGGERA`: adres IP urządzenia SmartESS
- `REGISTER`: adres startowy rejestru (int)
- `--count`: liczba rejestrów do odczytu (domyślnie 1)
- `--localip`: wymuszony lokalny adres interfejsu (autodetekcja jeśli brak)
- `--tcp-port`: port TCP (domyślnie 502)
- `--udp-port`: port UDP (domyślnie 58899)
- `--debug`: włącza dodatkowe logi
- `--set`: zapisuje wartości do kolejnych rejestrów od adresu `REGISTER`, np. `"230,250"` albo `"0x00e6,0x00fa"`

Bezpośredni odczyt (omijanie chmury)

- Skrypt komunikuje się bezpośrednio z lokalnym dataloggerem SmartESS/Dessmonitor i **nie** wysyła danych do chmury sprzedawcy.
- Wymaga, by komputer uruchamiający skrypt i datalogger znajdowały się w tej samej sieci LAN (lub miały trasę routingu). Host musi akceptować połączenia TCP na porcie określonym przez `--tcp-port` (domyślnie 502).
- Przebieg: skrypt wysyła UDP notify do urządzenia (`--udp-port`), urządzenie łączy się TCP do hosta, skrypt wysyła tunelowaną ramkę Modbus i odbiera odpowiedź.
- Uwaga na firewalle/NAT: jeśli host jest za NAT, uruchom skrypt na maszynie w tej samej sieci co datalogger lub udostępnij publiczny adres/port.
- Jeśli masz wiele interfejsów, użyj `--localip` by wskazać konkretny lokalny adres IP.

Funkcje (skrót)

- `smartess_read(...)` — jednorazowy odczyt, zgodny z poprzednim interfejsem
- `smartess_write(...)` — jednorazowy zapis wielu rejestrów
- `smartess_open_session(...)` — otwiera utrzymywaną sesję TCP
- `SmartESSSession` — sesja do wielu odczytów/zapisów bez ponownego UDP notify i accept TCP
- `smartess_protocol.py` — niskopoziomowe funkcje protokołu: UDP notify, TCP accept, CRC, budowa ramek i parsowanie odpowiedzi

Wersja

- `1.1.1` — refaktor warstwy protokołu do `smartess_protocol.py`, obsługa zapisu rejestrów, opcjonalna utrzymywana sesja TCP i rozszerzony opis użycia.
- `1.0` — pierwsze wydanie: podstawowy klient do odczytu rejestrów z dataloggera SmartESS/Dessmonitor.

Contributing
Proste PRy i poprawki dokumentacji — mile widziane.

Licencja
Projekt objęty licencją zawartą w pliku `LICENSE`.
