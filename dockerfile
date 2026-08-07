FROM python:3.14.7-slim-bookworm

# Install zmap and whois
RUN sudo apt-get update && sudo apt-get install -y zmap whois

WORKDIR /app

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "src/mst/__main__.py"]