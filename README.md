# **Skaner sieciowy**
Projekt zostanie wykonany w języku Python, przewidujemy porównanie dwóch podejść do stworzenia skanera:

* Za pomocą pakietu Socket
* Za pomocą bibliotek i [scapy](https://github.com/secdev/scapy) implementacja skanowań zgodnych z instrukcją [nmap](https://nmap.org/book/man-port-scanning-techniques.html?fbclid=IwAR29bf22JMR1lJmB0TGtq2Mt7CEU7GR1VYZx_RS4senQhVm9KcYCCHalU6A)
    
    * TCP SYN scan - polega na wysyłaniu pakietów TCP z flagą SYN, bez zamiaru nawiązania pełnego połączenia. Otrzymanie pakietu z flagami SYN/ACK klasyfikuje port jako *open*, flagi RST jako *closed*,
      natomiast brak odpowiedzi przy kilku retransmisjach lub ICMP(type 3, code 0, 1, 2, 3, 9, 10, or 13) jako *filtered* 
    * UDP scan - polega na wysłaniu pustego pakietu UDP, otrzymanie zwrotnego pakietu UDP klasyfikuje port jako *open*, wiadomość ICMP(type 3, code 3) oznacza port jako *closed*, wiadomość ICMP(type 3, code 0, 1, 2, 9, 10, or 13) *filtered*, brak reakcji definiuje port jako *open|filtered*
    * TCP ACK scan - polega na wysłaniu pakietu TCP z flagą ACK, służy tylko do wykrywania czy port jest za firewallem, otrzymanie zwrotnego pakietu z flagą RST oznacz port jako *unfiltered*, nie otrzymanie odpowiedzi lub otrzymanie wiadomości ICMP(type 3, code 0, 1, 2, 3, 9, 10, or 13) klasyfikuje port jako *filtered*
    * TCP Window scan - analogiczna metoda do TCP ACK scan, różniąca się dodatkowym sprawdzaniem wartości pola Window w przypadku otrzymania pakietu z flagą RST, co pozwala oznaczyć port jako *open* jeśli wartość tego pola jest dodatnia oraz *closed* jeśli równa zero. Ta metoda działa tylko dla niektórych systemów.    

Dodatkowo skaner będzie wskazywał przewidywany system operacyjny skanowanej maszyny na podstawie pól TTL i Window size.

# **Testowanie**
Wynikiem testu jest określenie dostępności portu:

* open - aplikacja aktywnie odbiera połączenia na danym porcie
* closed - port odbiera połączenia, ale żadna aplikacja nie nasłuchuje
* filtered - port znajduje się za firewawllem
* unfiltered - port jest dostępny, ale nie można wykryć czy nasłuchuje na nim jakaś aplikacja
* open|filtered - nie można określić, czy port jes otwarty, czy schowany za firewallem
    
# **Uruchamianie i przebieg testów**
Skanowanie przebiega dwufazowo. Ze względu na czas skanowania, najpierw skanowanie za pomocą protokołu ICMP ustala dostępne hosty w podanej sieci, arumentem są pierwsze 3 oktety zapisane dziesiętnie wraz z kropkami. Aktualnie maska domyślna, niezmienna /24.
Dla poprawności wykrycia hostów, skanowane maszyny nie powinny mieć ustawionego firewalla.

        sudo python3 ICMPping.py xxx.xxx.xxx.
        
Następnie należy skonfigurować firewalle na skanowanych maszynach. I wykonać właściwe skanowanie.

        sudo python3 BCYBScanner.py arg
        
arg:
-a ACK scan
-f FIN scan
-S socket scan
-s SYN scan
-t TCP handshake scan
-u UDP scan
-w window scan
-x XMAS scan