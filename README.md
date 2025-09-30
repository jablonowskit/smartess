SmartESS — lekki klient w Pythonie do odczytu rejestrów Modbus z dataloggera SmartESS/Dessmonitor. Obsługuje tunelowanie Modbus RTU przez Modbus TCP (protokół specyficzny dla urządzenia) i zwraca wynik jako JSON.

Wymagania

- Python 3.7+

Opis
Skrypt `smartess_client.py`:

- wysyła UDP notify do dataloggera (port domyślny 58899),
- czeka na połączenie TCP od dataloggera (port domyślny 502),
- tuneluje żądanie Modbus RTU (funkcja 3 — odczyt holding registers) przez protokół Modbus TCP i parsuje odpowiedź,
- zwraca wynik jako JSON z timestampem.

Różnica względem Modbus

- **Modbus TCP**: MBAP (TID, PID, Length, Unit ID) + PDU (funkcja + dane), bez CRC; Unit ID w MBAP służy jako adres slave.
- **Modbus RTU**: ramka serialowa: Unit ID + PDU + CRC16 (2 bajty, little-endian).
- **SmartESS (tunel)**: używa MBAP, ale PDU ma prefiks `0x04 0x01` i zawiera **RTU PDU + CRC** — CRC RTU jest zachowany wewnątrz tunelu. Oznacza to, że nie można traktować tego ruchu jak zwykły Modbus TCP: trzeba obsłużyć prefiks tunelowania oraz obliczać/weryfikować CRC RTU.

Użycie
python smartess_client.py <IP_DATALOGGERA> <REGISTER> [--count N] [--localip X.X.X.X] [--tcp-port 502] [--udp-port 58899] [--debug]

Przykład
python smartess_client.py 192.168.1.50 100 --count 2

Wyjście przykładowe:
{"ts":"2025-09-30T12:00:00","100":123,"101":-5}

Argumenty

- `IP_DATALOGGERA`: adres IP urządzenia SmartESS
- `REGISTER`: adres startowy rejestru (int)
- `--count`: liczba rejestrów do odczytu (domyślnie 1)
- `--localip`: wymuszony lokalny adres interfejsu (autodetekcja jeśli brak)
- `--tcp-port`: port TCP (domyślnie 502)
- `--udp-port`: port UDP (domyślnie 58899)
- `--debug`: włącza dodatkowe logi

Bezpośredni odczyt (omijanie chmury)

- Skrypt komunikuje się bezpośrednio z lokalnym dataloggerem SmartESS/Dessmonitor i **nie** wysyła danych do chmury sprzedawcy.
- Wymaga, by komputer uruchamiający skrypt i datalogger znajdowały się w tej samej sieci LAN (lub miały trasę routingu). Host musi akceptować połączenia TCP na porcie określonym przez `--tcp-port` (domyślnie 502).
- Przebieg: skrypt wysyła UDP notify do urządzenia (`--udp-port`), urządzenie łączy się TCP do hosta, skrypt wysyła tunelowaną ramkę Modbus i odbiera odpowiedź.
- Uwaga na firewalle/NAT: jeśli host jest za NAT, uruchom skrypt na maszynie w tej samej sieci co datalogger lub udostępnij publiczny adres/port.
- Jeśli masz wiele interfejsów, użyj `--localip` by wskazać konkretny lokalny adres IP.

Funkcje (skrót)

- `send_udp_notify(...)` — wysyła UDP notify do dataloggera
- `wait_for_datalogger_connection(...)` — otwiera nasłuch TCP i akceptuje połączenie
- `build_tunneled_request(...)` — buduje tunelowaną ramkę Modbus
- `read_one_modbus_tcp_frame(...)` — odbiera jedną ramkę Modbus/TCP
- `parse_tunneled_response(...)` — parsuje odpowiedź tunelowaną
- `smartess_read(...)` — główna funkcja używana przez CLI

Wersja

- `1.0` — pierwsze wydanie: podstawowy klient do odczytu rejestrów z dataloggera SmartESS/Dessmonitor.

Contributing
Proste PRy i poprawki dokumentacji — mile widziane.

Licencja
Projekt objęty licencją zawartą w pliku `LICENSE`.
