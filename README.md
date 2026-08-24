# Secure File Share

A small, deployable secure file-sharing web app with:

- User signup/login
- AES-256-GCM encryption at rest
- Password-protected, one-time share links
- Configurable share expiry (1–168 hours)
- SHA-256 integrity checksum
- 50 MB default upload limit
- Health endpoints for containers/Kubernetes
- No committed users, sessions, uploads, or secrets

> **Important:** this project is a demonstration/reference implementation. The built-in upload scan status is only a placeholder; connect a real malware scanner before treating it as production security software.

## Project structure

```text
secure-file-share/
├── src/
│   ├── server.py
│   └── public/
│       ├── index.html
│       ├── app.js
│       └── styles.css
├── k8s/
│   ├── namespace.yaml
│   ├── secret.example.yaml
│   ├── pvc.yaml
│   ├── deployment.yaml
│   └── service.yaml
├── .env.example
├── .gitignore
├── Dockerfile
├── requirements.txt
└── README.md
```

## Run locally on Windows PowerShell

### 1. Create a virtual environment

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Generate an AES-256 key

```powershell
$env:ENCRYPTION_KEY = python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
$env:STORAGE_DIR = "$PWD\data"
$env:PORT = "3000"
```

Keep the key private. Do not commit it.

### 3. Start the server

```powershell
python .\src\server.py
```

Open `http://localhost:3000`.

Health check:

```powershell
Invoke-RestMethod http://localhost:3000/healthz/readiness
```

## Run with Docker

Generate a key first:

```powershell
$key = python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
docker build -t secure-file-share:local .
docker run --rm -p 3000:3000 -e ENCRYPTION_KEY=$key -v "${PWD}\data:/data" secure-file-share:local
```

Then open `http://localhost:3000`.

## GitHub

GitHub stores the source code, but **GitHub Pages cannot run this Python backend**. Use GitHub for the repository and deploy the container to Kubernetes/OpenShift or another container host.

```powershell
git init
git add .
git commit -m "Prepare secure file share for deployment"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/secure-file-share.git
git push -u origin main
```

## Kubernetes / OpenShift

The manifests in `k8s/` are intentionally minimal. Create the namespace, secret, persistent storage, deployment and service.

1. Build and publish the container image.
2. Update the image in `k8s/deployment.yaml`.
3. Create the encryption secret from `k8s/secret.example.yaml`.
4. Apply the manifests:

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/secret.example.yaml
kubectl apply -f k8s/pvc.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
```

For OpenShift, use `oc` instead of `kubectl`. Add a Route after the service is running:

```bash
oc expose service/secure-file-share -n secure-file-share
oc get route -n secure-file-share
```

### Persistent storage

The application stores encrypted payloads and its small JSON metadata store in `STORAGE_DIR`. For more than one replica, use a storage class that supports the required shared access mode and consider replacing the JSON state store with PostgreSQL/Redis.

## Security notes

- Never commit `.env`, encryption keys, `app_state.json`, or uploaded files.
- Passwords are stored with PBKDF2-HMAC-SHA256, not plain SHA-256.
- Uploaded content is encrypted with AES-256-GCM before it is written to disk.
- Share downloads are one-time and delete the stored encrypted payload afterward.
- Expired shares are removed when accessed.
- A real malware scanner should run before a file is made downloadable.
- Use HTTPS at the deployment layer.
- For a multi-replica production deployment, replace the JSON file store with a proper database and use shared object storage for files.

## Troubleshooting

**`ENCRYPTION_KEY is required`**

Generate a new 32-byte base64 key and set it in the environment before starting the app.

**Port already in use**

```powershell
$env:PORT = "3001"
python .\src\server.py
```

**Old test accounts/files appear**

They are deliberately not included in this repository. The cleaned project starts with an empty data directory.
