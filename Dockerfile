FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENTRYPOINT ["python", "EoLPackageScanner.py", "/sbom/sbom.json"]