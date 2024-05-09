# Używamy oficjalnego obrazu Pythona jako obrazu bazowego
FROM python:3.9-slim

# Ustawiamy katalog roboczy w kontenerze
WORKDIR /app

# Kopiowanie plików 'requirements.txt.txt' i instalacja zależności
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Kopiowanie reszty plików aplikacji do katalogu roboczego
COPY . .

# Informujemy Docker, że kontener nasłuchuje na porcie 5000
EXPOSE 5000

# Określamy polecenie, które uruchamia aplikację
CMD ["flask", "run", "--host=0.0.0.0"]
