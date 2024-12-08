# Ton Andreea-Ioana 333CA

## Tema 4 - PCOM

### Descrierea functionalitatii

Am realizat implementarea efectiva a comenzilor in fisierul client.c
buffer.c, buffer.h, helpers.c, helpers.h,request.c si request.h fiind
preluate din cadrul laboratorului

Am realizat parsarea payload-urilor JSON manual, concatenand in format
JSON datele pentru useri si carti.
In main astept introducere unei comenzi noi pana la introducerea comezii
de exit. La introducerea unei comenzi se apeleaza o functie care trateaza
acel caz. 
Pentru fiecare comanda tratez daca am permisiunea de a o realiza
(daca userul este logat, daca am intrat in biblioteca si o pot accesa).
In cazul in care am permisiunea deschid conexiunea catre server,lansez
un request, iar dupa primirea raspunsului il analizez pentru a vedea daca 
trebuie afisat un mesaj de eroare.
Am tratat separat si cazurile in care numarul de pagini nu este un numar,
sau detaliile care trebuie introduse despre carte nu sunt valide sau 
userul nu este valid. In aceste cazuri am afisat de asemenea un mesaj
de eroare.

