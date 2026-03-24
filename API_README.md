# MUTY Transporte API

API Python (FastAPI) para o dashboard MUTY Transporte Escolar 2026.

## Endpoints

| Método | Rota | Descrição |
|--------|------|-----------|
| GET | `/` | Health check |
| GET | `/todos` | Carrega todos os dados de uma vez |
| GET | `/pagamentos` | Lista pagamentos |
| PUT | `/pagamentos` | Salva pagamentos |
| GET | `/despesas` | Lista despesas |
| PUT | `/despesas` | Salva despesas |
| GET | `/clientes` | Lista clientes (ordem alfabética) |
| PUT | `/clientes` | Salva clientes |

## Deploy no Render.com

1. Crie conta em https://render.com
2. New → Web Service → conecte este repositório
3. Configure:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn main:app --host 0.0.0.0 --port $PORT`
4. Adicione variável de ambiente:
   - `MONGO_URL` = sua connection string do MongoDB Atlas

## Variáveis de Ambiente

| Variável | Descrição |
|----------|-----------|
| `MONGO_URL` | Connection string do MongoDB Atlas |
