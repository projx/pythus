# Pythus - Service Health Monitor

Pythus is a Python-based service health monitoring tool that helps you monitor the status of various network services. It supports monitoring HTTP(S) endpoints, DNS servers, and more.

## Features

- Monitor HTTP and HTTPS endpoints
- Monitor DNS servers
- Configurable monitoring intervals
- Condition-based health checks
- Modern web dashboard
- REST API endpoints
- Real-time updates

## Installation

1. Create a virtual environment:
```bash
python -m venv /Users/kelvin/Prog/virtualenvs/pythus
```

2. Activate the virtual environment:
```bash
source /Users/kelvin/Prog/virtualenvs/pythus/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

Create a `config.yaml` file with your endpoints. Example:

```yaml
endpoints:
  - name: google
    group: external
    url: "https://www.google.com"
    interval: 1m
    conditions:
      - "[STATUS] == 200"
      - "[RESPONSE_TIME] < 1000"

  - name: cloudflare-dns
    group: dns
    url: "8.8.8.8"
    interval: 5m
    dns:
      query-name: "cloudflare.com"
      query-type: "A"
    conditions:
      - "[DNS_RCODE] == NOERROR"
```

## Running the Application

1. Make sure your virtual environment is activated
2. Run the application:
```bash
python -m pythus
```

The web interface will be available at `http://localhost:8080`

## API Endpoints

- `GET /`: Web dashboard
- `GET /api/endpoints`: List all endpoints and their current status
- `GET /api/endpoints/{name}/history`: Get historical data for a specific endpoint

## Contributing

Feel free to submit issues and enhancement requests!
