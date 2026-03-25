# ==============================================================================
# TRAJETO — API v3.0
# ------------------------------------------------------------------------------
# Stack  : FastAPI + MongoDB Atlas + PyJWT + bcrypt + Resend (email) + Gemini OCR
# Deploy : Render.com (free tier — usa Resend via HTTPS, sem SMTP nativo)
# Banco  : muty2026 no MongoDB Atlas M0
# Autor  : Erondino Meireles Lima
#
# v3.0 — reestruturacao SaaS Trajeto (2026-03-23):
#   - Rebranding: MUTY Transporte -> Trajeto
#   - Perfil de usuario: escolar | taxi | frota | autonomo
#   - Planos: free (anuncios) e plus (sem anuncios + OCR + extrato)
#   - OCR e nota-fiscal: restritos ao plano Plus
#   - /v2/meu-plano    : retorna plano atual e beneficios
#   - /v2/upgrade      : gera link MP (inativo ate MERCADOPAGO_ACTIVE=true)
#   - /v2/webhook/mercadopago : recebe notificacao de pagamento (inativo)
# ==============================================================================

# ── IMPORTS PADRÃO ────────────────────────────────────────────────────────────
import os
import re
import uuid
import base64
import json
import secrets
import traceback
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs

# ── IMPORTS DE TERCEIROS ──────────────────────────────────────────────────────
import httpx
import bcrypt
import jwt as pyjwt                          # PyJWT — mais estável que python-jose

from email_validator import validate_email, EmailNotValidError

from fastapi import FastAPI, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from pymongo import MongoClient, ASCENDING
from pymongo.errors import DuplicateKeyError

# ═══════════════════════════════════════════════════════════════════════════════
# SEÇÃO 1 — CONFIGURAÇÃO GLOBAL
# Todas as variáveis de ambiente ficam aqui. Nunca espalhar os.environ.get()
# pelo código — dificulta manutenção e auditoria de segurança.
# ═══════════════════════════════════════════════════════════════════════════════

# Segurança: troque JWT_SECRET em produção via variável de ambiente no Render
SECRET_KEY      = os.environ.get("JWT_SECRET",    "muty-secret-dev-2026-TROCAR-em-producao")
ALGORITHM       = "HS256"
TOKEN_HOURS     = 8    # JWT expira em 8 horas
VERIFY_HOURS    = 24   # token de verificação de email expira em 24 horas
RESET_HOURS     = 2    # token de reset de senha expira em 2 horas

# Serviços externos (configurar no Render → Environment Variables)
GEMINI_API_KEY  = os.environ.get("GEMINI_API_KEY",   "")  # NUNCA expor no frontend
GEMINI_API_KEY2 = os.environ.get("GEMINI_API_KEY_2", "")  # chave de backup para rotacao
GEMINI_API_KEY3 = os.environ.get("GEMINI_API_KEY_3", "")  # chave de backup extra
RESEND_API_KEY  = os.environ.get("RESEND_API_KEY",   "")  # Resend: envio de email via HTTPS
MONGO_URL       = os.environ.get("MONGO_URL",        "")  # connection string do Atlas

# Mercado Pago - pagamentos de assinatura Plus
# MERCADOPAGO_ACTIVE=false => endpoints existem mas retornam "em breve"
MERCADOPAGO_TOKEN  = os.environ.get("MERCADOPAGO_TOKEN",  "")
MERCADOPAGO_ACTIVE = os.environ.get("MERCADOPAGO_ACTIVE", "false").lower() == "true"

# Preco do plano Plus em centavos (R$ 29,90 = 2990)
PLUS_PRECO_CENTAVOS = int(os.environ.get("PLUS_PRECO_CENTAVOS", "2990"))
PLUS_PRECO_LABEL    = os.environ.get("PLUS_PRECO_LABEL", "R$ 29,90/mes")

# URL do frontend - usada nos redirects pos verificacao de email e reset de senha
FRONTEND_URL = os.environ.get(
    "FRONTEND_URL",
    "https://meirelesnew.github.io/muty-transporte-2026"
)

# Build - atualizar manualmente a cada deploy significativo
BUILD_TAG = "20260323-v3.0"

# auto_error=False: não lança 403 automaticamente — tratamos o erro manualmente
# para dar mensagens em português mais claras ao frontend.
bearer_ = HTTPBearer(auto_error=False)

# ═══════════════════════════════════════════════════════════════════════════════
# SEÇÃO 2 — VALIDAÇÕES
# Funções puras que validam dados de entrada. Retornam (bool, mensagem).
# Separadas dos endpoints para facilitar testes unitários.
# ═══════════════════════════════════════════════════════════════════════════════

def validar_email_fmt(email: str) -> tuple[bool, str]:
    """
    Valida formato e domínio do email usando a lib email-validator.
    Retorna (True, email_normalizado) ou (False, mensagem_de_erro).
    O email normalizado já vem em lowercase e sem espaços extras.
    """
    try:
        info = validate_email(email, check_deliverability=False)
        return True, info.normalized
    except EmailNotValidError as e:
        return False, str(e)


def validar_senha(senha: str) -> tuple[bool, str]:
    """
    Valida requisitos mínimos de senha forte:
    - Mínimo 6 caracteres
    - Pelo menos 1 letra maiúscula
    - Pelo menos 1 letra minúscula
    - Pelo menos 1 número
    - Pelo menos 1 caractere especial
    Retorna (True, "") ou (False, mensagem_de_erro).
    """
    if len(senha) < 6:
        return False, "Senha deve ter no mínimo 6 caracteres"
    if not re.search(r'[A-Z]', senha):
        return False, "Senha deve ter pelo menos 1 letra maiúscula"
    if not re.search(r'[a-z]', senha):
        return False, "Senha deve ter pelo menos 1 letra minúscula"
    if not re.search(r'\d', senha):
        return False, "Senha deve ter pelo menos 1 número"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>\-_=+\[\];\'`~/\\]', senha):
        return False, "Senha deve ter pelo menos 1 caractere especial (!@#$%...)"
    return True, ""


# ═══════════════════════════════════════════════════════════════════════════════
# SEÇÃO 3 — SEGURANÇA: HASHING E JWT
# bcrypt direto (sem passlib) para evitar o bug de truncamento em 72 bytes.
# ═══════════════════════════════════════════════════════════════════════════════

def hash_senha(senha: str) -> str:
    """
    Gera hash bcrypt da senha.
    str() antes de encode() garante que mesmo valores não-string
    sejam processados sem erro.
    """
    return bcrypt.hashpw(str(senha).encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verificar_senha(senha: str, hashed: str) -> bool:
    """
    Compara senha em texto plano com o hash armazenado.
    Retorna False em qualquer exceção — nunca expõe o erro ao chamador.
    """
    try:
        return bcrypt.checkpw(
            str(senha).encode("utf-8"),
            str(hashed).encode("utf-8")
        )
    except Exception as e:
        print(f"[AUTH] Erro verificar_senha: {e}")
        return False


def criar_token(user_id: str, email: str) -> str:
    """Gera JWT assinado. Payload: sub (user_id), email, exp (expiração)."""
    expire  = datetime.utcnow() + timedelta(hours=TOKEN_HOURS)
    payload = {"sub": user_id, "email": email, "exp": expire}
    return pyjwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decodificar_token(token: str) -> dict:
    """
    Decodifica e valida JWT.
    Distingue token expirado de token inválido para mensagens melhores.
    """
    try:
        return pyjwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado — faça login novamente")
    except Exception:
        raise HTTPException(status_code=401, detail="Token inválido")


# ═══════════════════════════════════════════════════════════════════════════════
# SEÇÃO 4 — BANCO DE DADOS (MongoDB Atlas)
# Singleton com lazy init: a conexão só é criada na primeira requisição,
# evitando falha de startup no Render free tier (cold start lento).
# ═══════════════════════════════════════════════════════════════════════════════

_mongo_client: MongoClient | None = None


def get_db():
    """
    Retorna a instância do banco muty2026.
    Cria conexão e índices na primeira chamada (singleton).

    Índices:
    - users.email: único — impede cadastro duplicado
    - dados_v2.(user_id + tipo): único composto — 1 doc por tipo por usuário
    """
    global _mongo_client
    if _mongo_client is None:
        if not MONGO_URL:
            raise RuntimeError("MONGO_URL não configurada — adicione no Render → Environment")
        _mongo_client = MongoClient(MONGO_URL, serverSelectionTimeoutMS=10_000)
        db = _mongo_client["muty2026"]
        # try/except: se os índices já existirem no Atlas, ignora o erro
        try:
            db.users.create_index([("email", ASCENDING)], unique=True)
            db.dados_v2.create_index(
                [("user_id", ASCENDING), ("tipo", ASCENDING)],
                unique=True
            )
        except Exception:
            pass
    return _mongo_client["muty2026"]


# ═══════════════════════════════════════════════════════════════════════════════
# SEÇÃO 5 — AUTENTICAÇÃO: MIDDLEWARE JWT
# Dependency injection — endpoints com user=Depends(get_current_user) exigem JWT.
# ═══════════════════════════════════════════════════════════════════════════════

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_)
) -> dict:
    """
    Extrai e valida o JWT do header Authorization: Bearer <token>.
    Retorna dict {"user_id": ..., "email": ...} para uso nos endpoints.
    """
    if not credentials:
        raise HTTPException(status_code=401, detail="Token não fornecido")
    payload = decodificar_token(credentials.credentials)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Token inválido — campo 'sub' ausente")
    return {"user_id": user_id, "email": payload.get("email", "")}


# ═══════════════════════════════════════════════════════════════════════════════
# SEÇÃO 6 — HELPERS: DADOS ISOLADOS POR USUÁRIO (coleção dados_v2)
# Filtro sempre usa {user_id + tipo} — nunca mistura dados entre contas.
# ═══════════════════════════════════════════════════════════════════════════════

def _get_dados(db, user_id: str, tipo: str):
    """
    Busca dados de um usuário por tipo (pagamentos, despesas, clientes).
    Retorna o conteúdo de doc["dados"] ou None se ainda não existir.
    """
    doc = db.dados_v2.find_one({"user_id": user_id, "tipo": tipo})
    return doc["dados"] if doc else None


def _save_dados(db, user_id: str, tipo: str, dados) -> bool:
    """
    Salva dados com upsert atômico.
    upsert=True: cria o documento se não existir, atualiza se existir.
    Nunca há perda de dados por race condition.
    Retorna True se a operação foi confirmada pelo MongoDB.
    """
    try:
        result = db.dados_v2.update_one(
            {"user_id": user_id, "tipo": tipo},
            {"$set": {"dados": dados, "updated_at": datetime.utcnow()}},
            upsert=True
        )
        return result.acknowledged
    except Exception as e:
        print(f"[DB] Erro ao salvar tipo={tipo} user_id={user_id}: {e}")
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# SEÇÃO 7 — EMAIL (Resend API via HTTPS)
# Render free tier bloqueia SMTP (porta 25/587).
# Solução: Resend REST API na porta 443 — funciona sem restrição.
# ═══════════════════════════════════════════════════════════════════════════════

def _html_email(titulo: str, nome: str, mensagem: str, link: str, btn_texto: str) -> str:
    """
    Template HTML reutilizavel para emails transacionais.
    Design: fundo escuro (#0a0e17), acento ambar (#f59e0b), estilo Trajeto.
    Inclui link fallback em texto para clientes que bloqueiam botoes HTML.
    """
    return f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;
                background:#0a0e17;color:#e2e8f0;padding:32px;border-radius:16px;">
      <div style="text-align:center;margin-bottom:24px;">
        <div style="font-size:48px;">&#x1F6E3;</div>
        <h1 style="font-family:Impact,sans-serif;letter-spacing:2px;
                   color:#f59e0b;margin:8px 0;">TRAJETO</h1>
      </div>
      <h2 style="color:#e2e8f0;font-size:18px;">{titulo}</h2>
      <p style="color:#94a3b8;line-height:1.6;">{mensagem}</p>
      <div style="text-align:center;margin:32px 0;">
        <a href="{link}"
           style="background:#f59e0b;color:#000;padding:14px 32px;
                  border-radius:10px;text-decoration:none;
                  font-weight:bold;font-size:16px;letter-spacing:1px;">
          {btn_texto}
        </a>
      </div>
      <p style="color:#475569;font-size:12px;margin-top:8px;">
        Ou copie o link: <a href="{link}" style="color:#60a5fa;">{link}</a>
      </p>
      <p style="color:#64748b;font-size:11px;text-align:center;margin-top:24px;">
        Este link expira em 24 horas. Se voce nao solicitou isto, ignore este email.
      </p>
    </div>
    """


async def enviar_email(destino: str, assunto: str, html: str) -> bool:
    """
    Envia email via Resend API (HTTPS porta 443).
    Nunca lanca excecao — loga o erro e retorna False,
    para nao travar cadastro/reset por falha de email.
    """
    if not RESEND_API_KEY:
        print("[EMAIL] RESEND_API_KEY nao configurada — email nao enviado")
        return False
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                "https://api.resend.com/emails",
                headers={
                    "Authorization": f"Bearer {RESEND_API_KEY}",
                    "Content-Type":  "application/json",
                },
                json={
                    "from":    "Trajeto <noreply@curysolucoestecnicas.com.br>",
                    "to":      [destino],
                    "subject": assunto,
                    "html":    html,
                },
            )
            if resp.status_code in (200, 201):
                print(f"[EMAIL] Enviado — id={resp.json().get('id','?')} para={destino}")
                return True
            print(f"[EMAIL] Erro HTTP {resp.status_code}: {resp.text[:200]}")
            return False
    except Exception as e:
        print(f"[EMAIL] Excecao: {repr(e)}")
        return False


async def _email_verificacao(email: str, nome: str, token: str) -> bool:
    """Envia email de confirmacao de cadastro com link de verificacao."""
    link = f"{FRONTEND_URL}?verify_token={token}"
    html = _html_email(
        titulo    = f"Ola, {nome}! Confirme seu cadastro",
        nome      = nome,
        mensagem  = "Seu cadastro foi criado com sucesso. Clique abaixo para confirmar seu email e ativar a conta.",
        link      = link,
        btn_texto = "CONFIRMAR EMAIL",
    )
    return await enviar_email(email, "Confirme seu cadastro — Trajeto", html)


async def _email_reset_senha(email: str, nome: str, token: str) -> bool:
    """Envia email de redefinição de senha com link temporário."""
    link = f"{FRONTEND_URL}?reset_token={token}"
    html = _html_email(
        titulo    = f"Ola, {nome}! Redefinicao de senha",
        nome      = nome,
        mensagem  = "Recebemos uma solicitacao para redefinir a senha da sua conta. Clique abaixo para criar uma nova senha. Este link expira em 2 horas.",
        link      = link,
        btn_texto = "REDEFINIR SENHA",
    )
    return await enviar_email(email, "Redefinir senha — Trajeto", html)


# ═══════════════════════════════════════════════════════════════════════════════
# SEÇÃO 8 — OCR: HELPERS INTERNOS
# Pipeline: QR params → Gemini Vision → Regex local (fallback em cascata).
# Cada etapa retorna dict com as mesmas chaves para facilitar o merge final.
# ═══════════════════════════════════════════════════════════════════════════════

def _qr_extrair(qr_url: str) -> dict:
    """
    Extrai dados dos parâmetros da URL do QR Code da NFC-e.
    Instantâneo e gratuito — tenta antes de chamar Gemini.
    """
    dados: dict = {"estabelecimento": None, "valor_total": None, "data": None}
    try:
        params = parse_qs(urlparse(qr_url).query)
        for k in ("vNF", "valor", "vl", "total"):
            if k in params:
                try:
                    dados["valor_total"] = float(params[k][0].replace(",", "."))
                    break
                except ValueError:
                    pass
        for k in ("dhEmi", "data", "dt"):
            if k in params:
                raw = params[k][0]
                m = re.search(r"(\d{4})-(\d{2})-(\d{2})", raw)
                if m:
                    dados["data"] = f"{m.group(3)}/{m.group(2)}/{m.group(1)}"
                    break
                m = re.search(r"(\d{2}/\d{2}/\d{4})", raw)
                if m:
                    dados["data"] = m.group(1)
                    break
    except Exception as e:
        print(f"[OCR/QR] Erro: {e}")
    return dados


async def _gemini_ocr(b64: str, mime: str, chaves: list[str]) -> tuple[dict, str]:
    """
    Chama Gemini 1.5-flash para extrair dados do cupom fiscal.
    Tenta cada chave em ordem — rotação automática por cota (429).
    Retorna (dict_dados, texto_bruto_do_modelo).
    """
    vazio = {"estabelecimento": None, "valor_total": None, "data": None}
    if not chaves:
        print("[OCR/Gemini] Nenhuma chave configurada")
        return vazio, ""

    prompt = (
        "Voce e um especialista em leitura de cupons fiscais brasileiros (NFC-e, SAT, ECF).\n"
        "Analise a imagem e extraia:\n"
        "1. Nome do estabelecimento (razao social ou nome fantasia)\n"
        "2. Valor total pago (numero decimal, ex: 45.90)\n"
        "3. Data da compra (formato DD/MM/AAAA)\n\n"
        "Responda SOMENTE com JSON valido, sem markdown, sem explicacoes:\n"
        '{"estabelecimento": "...", "valor_total": 0.00, "data": "DD/MM/AAAA"}\n\n'
        "Se nao conseguir extrair um campo, use null."
    )

    for i, chave in enumerate(chaves):
        try:
            async with httpx.AsyncClient(timeout=25) as client:
                resp = await client.post(
                    f"https://generativelanguage.googleapis.com/v1beta/"
                    f"models/gemini-1.5-flash:generateContent?key={chave}",
                    json={
                        "contents": [{"parts": [
                            {"text": prompt},
                            {"inline_data": {"mime_type": mime, "data": b64}},
                        ]}],
                        "generationConfig": {"temperature": 0.1, "maxOutputTokens": 256},
                    },
                )

            if resp.status_code == 429:
                print(f"[OCR/Gemini] Chave {i+1} cota esgotada — tentando proxima")
                continue
            if resp.status_code != 200:
                print(f"[OCR/Gemini] Chave {i+1} HTTP {resp.status_code}")
                continue

            texto = resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
            # Remove markdown se o modelo desobedecer o prompt
            texto = re.sub(r"^```[a-z]*\n?", "", texto)
            texto = re.sub(r"\n?```$", "", texto).strip()

            dados_raw = json.loads(texto)

            # Normalizar valor_total: pode vir como string "45,90" ou float
            vt = dados_raw.get("valor_total")
            if isinstance(vt, str):
                try:
                    vt = float(vt.replace(",", "."))
                except ValueError:
                    vt = None

            return {
                "estabelecimento": dados_raw.get("estabelecimento") or None,
                "valor_total":     vt if vt and vt > 0 else None,
                "data":            dados_raw.get("data") or None,
            }, texto

        except json.JSONDecodeError:
            print(f"[OCR/Gemini] Chave {i+1} JSON invalido: {texto[:100]}")
            return vazio, texto
        except Exception as e:
            print(f"[OCR/Gemini] Chave {i+1} excecao: {repr(e)}")
            continue

    return vazio, ""


def _regex_extrair(texto: str) -> dict:
    """
    Extrai dados do cupom por regex — fallback quando Gemini não está disponível.
    Opera sobre o texto bruto do Gemini ou qualquer texto do cupom.
    """
    dados: dict = {"estabelecimento": None, "valor_total": None, "data": None}
    if not texto:
        return dados

    # Valor total — padrões específicos primeiro, R$ genérico como fallback
    for p in [
        r'(?:total|valor\s+total|total\s+a\s+pagar)\s*[:\-R$]*\s*([\d]{1,6}[.,][\d]{2})',
        r'R\$\s*([\d]{1,6}[.,][\d]{2})',
    ]:
        matches = re.findall(p, texto, re.IGNORECASE)
        valores = []
        for m in matches:
            try:
                v = float(m.replace(".", "").replace(",", "."))
                if 0.01 < v < 100_000:
                    valores.append(v)
            except ValueError:
                pass
        if valores:
            dados["valor_total"] = max(valores)
            break

    # Data — DD/MM/AAAA ou ISO AAAA-MM-DD
    m = re.search(r"(\d{2}/\d{2}/\d{4})", texto)
    if m:
        dados["data"] = m.group(1)
    else:
        m = re.search(r"(\d{4})-(\d{2})-(\d{2})", texto)
        if m:
            dados["data"] = f"{m.group(3)}/{m.group(2)}/{m.group(1)}"

    # Estabelecimento — rótulos textuais comuns
    m = re.search(r'(?:emitente|razao\s+social|empresa)[:\s]+([A-Z][^\n]{3,60})', texto, re.IGNORECASE)
    if m:
        dados["estabelecimento"] = m.group(1).strip()

    return dados


def _mesclar_fontes(fontes: list[tuple[str, dict]]) -> tuple[dict, list[str]]:
    """
    Mescla resultados de múltiplas fontes em um único dict.
    Prioridade: qr > gemini > regex.
    Campo já preenchido por fonte de maior prioridade não é sobrescrito.
    """
    final: dict       = {"estabelecimento": None, "valor_total": None, "data": None}
    fontes_usadas: list[str] = []

    for nome_fonte, dados in fontes:
        contribuiu = False
        for campo in final:
            if final[campo] is None and dados.get(campo) is not None:
                final[campo] = dados[campo]
                contribuiu = True
        if contribuiu:
            fontes_usadas.append(nome_fonte)
        if all(v is not None for v in final.values()):
            break  # todos os campos preenchidos — não precisa continuar

    return final, fontes_usadas


def _sugerir_categoria(nome: str) -> str:
    """Sugere categoria da despesa com base no nome do estabelecimento."""
    n = nome.lower() if nome else ""
    if any(x in n for x in ["posto", "combustivel", "petrobras", "shell", "ipiranga", "gnv", "gasolina"]):
        return "combustivel"
    if any(x in n for x in ["mecanica", "auto pecas", "pneu", "borracha", "oficina", "funilaria"]):
        return "manutencao"
    if any(x in n for x in ["detran", "ipva", "iptu", "multa", "tributo", "dpvat", "seguro"]):
        return "impostos"
    if any(x in n for x in ["pedagio", "ccr", "ecosul", "arteris"]):
        return "pedagio"
    if any(x in n for x in ["restaurante", "lanchonete", "padaria", "mercado", "supermercado"]):
        return "alimentacao"
    return "outros"


# ═══════════════════════════════════════════════════════════════════════════════
# SEÇÃO 9 — NOTA FISCAL: HELPERS INTERNOS (scraping do portal SEFAZ)
# ═══════════════════════════════════════════════════════════════════════════════

# Headers que simulam browser Android — evita bloqueios nos portais SEFAZ
_HEADERS_NF = {
    "User-Agent":                "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language":           "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding":           "gzip, deflate, br",
    "Connection":                "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Cache-Control":             "max-age=0",
    "Sec-Fetch-Dest":            "document",
    "Sec-Fetch-Mode":            "navigate",
    "Sec-Fetch-Site":            "none",
    "Sec-Fetch-User":            "?1",
}

# Mapa domínio → UF para identificar o estado da nota
_ESTADOS_NF = {
    "nfce.fazenda.sp.gov.br": "SP",
    "nfce.fazenda.rj.gov.br": "RJ",
    "nfe.fazenda.mg.gov.br":  "MG",
    "nfce.sefaz.rs.gov.br":   "RS",
    "nfce.sefaz.pr.gov.br":   "PR",
    "nfce.sefaz.ba.gov.br":   "BA",
    "nfce.sefaz.ce.gov.br":   "CE",
    "nfce.sefaz.pe.gov.br":   "PE",
}


def _detectar_estado(url: str) -> str:
    """Retorna a UF do estado com base no domínio da URL do QR Code."""
    for dominio, uf in _ESTADOS_NF.items():
        if dominio in url:
            return uf
    return "GENERICO"


def _limpar_html(texto: str) -> str:
    """Remove tags HTML e normaliza espaços em branco."""
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", texto)).strip()


def _nf_extrair_valor(html: str) -> float:
    """
    Extrai valor total da NFC-e com múltiplos padrões em cascata:
    1. Atributos data-* (portais modernos)
    2. Rótulos textuais comuns nos portais SEFAZ
    3. Qualquer R$ seguido de valor (fallback final)
    """
    m = re.search(
        r'data-(?:valor|total|preco)[^\s=]*\s*[=:]\s*["\']?([\d]+[.,][\d]{2})',
        html, re.IGNORECASE
    )
    if m:
        try:
            v = float(m.group(1).replace(",", "."))
            if 0.01 < v < 100_000:
                return v
        except ValueError:
            pass

    for p in [
        r'(?:Valor\s+Total|Total\s+da\s+Nota|Total\s+NF-e|Vl\.?\s*Total)\s*[:\-]?\s*R?\$?\s*([\d]{1,6}[.,][\d]{2})',
        r'(?:TOTAL|Total\s+a\s+Pagar|Total\s+Pagar)\s*[:\-]?\s*R?\$?\s*([\d]{1,6}[.,][\d]{2})',
        r'(?:Valor\s+a\s+Pagar|Pagar)\s*[:\-]?\s*R?\$?\s*([\d]{1,6}[.,][\d]{2})',
    ]:
        matches = re.findall(p, html, re.IGNORECASE)
        if matches:
            valores = []
            for raw in matches:
                try:
                    v = float(raw.replace(".", "").replace(",", "."))
                    if 0.01 < v < 100_000:
                        valores.append(v)
                except ValueError:
                    pass
            if valores:
                return max(valores)

    todos = []
    for raw in re.findall(r'R\$\s*([\d]{1,6}[.,][\d]{2})', html, re.IGNORECASE):
        try:
            v = float(raw.replace(".", "").replace(",", "."))
            if 0.01 < v < 100_000:
                todos.append(v)
        except ValueError:
            pass
    return max(todos) if todos else 0.0


def _nf_extrair_estabelecimento(html: str) -> str:
    """
    Extrai o nome do estabelecimento da NFC-e.
    Padrão 1: classes CSS específicas de portais NFC-e
    Padrão 2: rótulos textuais (Razão Social, Emitente...)
    Padrão 3: primeiro <h1> ou <strong> da página
    """
    for p in [
        r'<[^>]*class="[^"]*(?:NomeEmit|nome-emit|razaoSocial|nomeEmpresa|nome_emit)[^"]*"[^>]*>(.*?)</',
        r'<[^>]*id="[^"]*(?:NomeEmit|nomeEmit|razaoSocial)[^"]*"[^>]*>(.*?)</',
    ]:
        m = re.search(p, html, re.IGNORECASE | re.DOTALL)
        if m:
            texto = _limpar_html(m.group(1))
            if 3 < len(texto) < 120:
                return texto

    for p in [
        r'(?:Razao\s+Social|Emitente|Empresa)[:\s]+([A-Z][^<\n]{3,80})',
        r'<title[^>]*>([^<]{5,80})</title>',
    ]:
        m = re.search(p, html, re.IGNORECASE)
        if m:
            texto = _limpar_html(m.group(1)).strip()
            if 3 < len(texto) < 120:
                return texto

    for tag in [r'<h1[^>]*>(.*?)</h1>', r'<strong[^>]*>(.*?)</strong>']:
        m = re.search(tag, html, re.IGNORECASE | re.DOTALL)
        if m:
            texto = _limpar_html(m.group(1))
            if 3 < len(texto) < 120:
                return texto

    return "Estabelecimento"


def _nf_extrair_data(html: str) -> str:
    """Extrai data da NFC-e. Tenta DD/MM/AAAA depois ISO AAAA-MM-DD."""
    m = re.search(r"(\d{2}/\d{2}/\d{4})", html)
    if m:
        return m.group(1)
    m = re.search(r"(\d{4})-(\d{2})-(\d{2})", html)
    if m:
        return f"{m.group(3)}/{m.group(2)}/{m.group(1)}"
    return ""


# ═══════════════════════════════════════════════════════════════════════════════
# SEÇÃO 10 — APLICAÇÃO FastAPI
# ═══════════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title       = "Trajeto API",
    version     = "3.0",
    description = "API do sistema Trajeto — gestao financeira para motoristas e frotas",
)

# CORS restrito para impedir conexões de aplicativos maliciosos de terceiros
app.add_middleware(
    CORSMiddleware,
    allow_origins  = [
        "https://meirelesnew.github.io",
        "http://localhost:8080",
        "http://127.0.0.1:8080"
    ],
    allow_methods  = ["*"],
    allow_headers  = ["*"],
)


# ═══════════════════════════════════════════════════════════════════════════════
# SEÇÃO 11 — ENDPOINTS DE SAÚDE (sem autenticação)
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/")
@app.get("/health")
def health():
    """Health check — Render usa este endpoint para monitorar o servico."""
    return {"status": "ok", "app": "Trajeto API", "versao": "3.0", "build": BUILD_TAG}


@app.get("/health/db")
def health_db():
    """Verifica se o MongoDB Atlas está acessível."""
    try:
        get_db().command("ping")
        return {"status": "ok", "mongo": "conectado"}
    except Exception as e:
        # Retorna 200 com status=erro para não derrubar o Render
        return {"status": "erro", "mongo": str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
# SEÇÃO 12 — ENDPOINTS V1 LEGADOS (sem autenticação — compatibilidade)
# ATENCAO: dados compartilhados entre todos os usuários. Migrar para /v2/.
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/todos")
def v1_get_todos():
    """Retorna todos os dados da colecao compartilhada (legado)."""
    db   = get_db()
    docs = {doc["_id"]: doc["dados"] for doc in db.dados.find()}
    return {
        "pagamentos": docs.get("pagamentos", {}),
        "despesas":   docs.get("despesas", []),
        "clientes":   sorted(docs.get("clientes", []), key=lambda c: c.get("nome", "").lower()),
    }


@app.get("/pagamentos")
def v1_get_pagamentos():
    doc = get_db().dados.find_one({"_id": "pagamentos"})
    return {"dados": doc["dados"] if doc else {}}


@app.get("/despesas")
def v1_get_despesas():
    doc = get_db().dados.find_one({"_id": "despesas"})
    return {"dados": doc["dados"] if doc else []}


@app.get("/clientes")
def v1_get_clientes():
    doc      = get_db().dados.find_one({"_id": "clientes"})
    clientes = doc["dados"] if doc else []
    return {"dados": sorted(clientes, key=lambda c: c.get("nome", "").lower())}


@app.put("/pagamentos")
async def v1_save_pagamentos(request: Request):
    dados = await request.json()
    get_db().dados.update_one({"_id": "pagamentos"}, {"$set": {"dados": dados, "ts": datetime.utcnow()}}, upsert=True)
    return {"ok": True}


@app.put("/despesas")
async def v1_save_despesas(request: Request):
    dados = await request.json()
    get_db().dados.update_one({"_id": "despesas"}, {"$set": {"dados": dados, "ts": datetime.utcnow()}}, upsert=True)
    return {"ok": True}


@app.put("/clientes")
async def v1_save_clientes(request: Request):
    dados = await request.json()
    if isinstance(dados, list):
        dados = sorted(dados, key=lambda c: c.get("nome", "").lower())
    get_db().dados.update_one({"_id": "clientes"}, {"$set": {"dados": dados, "ts": datetime.utcnow()}}, upsert=True)
    return {"ok": True}


# ═══════════════════════════════════════════════════════════════════════════════
# SEÇÃO 13 — ENDPOINTS V2: AUTENTICAÇÃO
# ═══════════════════════════════════════════════════════════════════════════════

# Perfis validos de usuario
PERFIS_VALIDOS = {"escolar", "taxi", "frota", "autonomo"}

# Rotulos do modulo 'clientes' por perfil
PERFIL_LABELS = {
    "escolar":  {"clientes": "Alunos",    "cliente": "Aluno",    "icone": "🎒"},
    "taxi":     {"clientes": "Corridas",  "cliente": "Corrida",  "icone": "🚕"},
    "frota":    {"clientes": "Veiculos",  "cliente": "Veiculo",  "icone": "🚚"},
    "autonomo": {"clientes": "Servicos",  "cliente": "Servico",  "icone": "🔧"},
}


def _is_plus(db, user_id: str) -> bool:
    """
    Verifica se o usuario possui plano Plus ativo.
    Retorna False em qualquer erro — nunca bloqueia indevidamente.
    """
    try:
        user = db.users.find_one({"user_id": user_id}, {"plano": 1})
        return user and user.get("plano") == "plus"
    except Exception:
        return False


@app.post("/v2/register")
async def register(request: Request):
    """
    Cadastro de novo usuario.
    Fluxo: validar nome -> validar email -> validar senha ->
           inserir no MongoDB -> enviar email de verificacao -> retornar confirmacao.
    Campo perfil: escolar | taxi | frota | autonomo (padrao: escolar)
    """
    try:
        body    = await request.json()
        nome    = str(body.get("nome",    "")).strip()
        email   = str(body.get("email",   "")).strip()
        senha   = str(body.get("senha",   ""))
        empresa = str(body.get("empresa", "")).strip()
        perfil  = str(body.get("perfil",  "escolar")).strip().lower()

        if perfil not in PERFIS_VALIDOS:
            perfil = "escolar"  # fallback seguro

        if not nome:
            return {"status": "error", "message": "Nome e obrigatorio"}

        ok_email, resultado_email = validar_email_fmt(email)
        if not ok_email:
            return {"status": "error", "message": f"Email invalido: {resultado_email}"}
        email = resultado_email  # email normalizado (lowercase, sem espacos)

        ok_senha, msg_senha = validar_senha(senha)
        if not ok_senha:
            return {"status": "error", "message": msg_senha}

        db            = get_db()
        user_id       = str(uuid.uuid4())
        verify_token  = secrets.token_urlsafe(32)
        verify_expira = datetime.utcnow() + timedelta(hours=VERIFY_HOURS)

        try:
            db.users.insert_one({
                "user_id":       user_id,
                "email":         email,
                "senha_hash":    hash_senha(senha),
                "nome":          nome,
                "empresa":       empresa,
                "perfil":        perfil,
                "plano":         "free",
                "ativo":         True,
                "is_verified":   False,
                "verify_token":  verify_token,
                "verify_expira": verify_expira,
                "created_at":    datetime.utcnow(),
            })
        except DuplicateKeyError:
            return {"status": "error", "message": "Email ja cadastrado"}

        email_enviado = await _email_verificacao(email, nome, verify_token)
        print(f"[AUTH] Cadastro: {email} | perfil={perfil} | email_enviado={email_enviado}")
        return {
            "status": "success",
            "data": {
                "user_id":       user_id,
                "nome":          nome,
                "email":         email,
                "empresa":       empresa,
                "perfil":        perfil,
                "plano":         "free",
                "is_verified":   False,
                "email_enviado": email_enviado,
                "mensagem":      "Cadastro criado! Verifique seu email para ativar a conta.",
            }
        }
    except Exception as e:
        traceback.print_exc()
        return {"status": "error", "message": f"Erro no cadastro: {str(e)}"}


@app.post("/v2/login")
async def login(request: Request):
    """
    Login com email e senha. Retorna JWT válido por TOKEN_HOURS horas.
    BUG CORRIGIDO: verificação em condição única — não revela qual campo falhou.
    """
    try:
        body  = await request.json()
        email = str(body.get("email", "")).strip().lower()
        senha = str(body.get("senha", ""))

        if not email or not senha:
            return {"status": "error", "message": "Email e senha sao obrigatorios"}

        db   = get_db()
        user = db.users.find_one({"email": email})

        # Verifica credenciais sem revelar qual campo está errado (anti-enumeração)
        if not user or not verificar_senha(senha, user.get("senha_hash", "")):
            return {"status": "error", "message": "Email ou senha incorretos"}

        if not user.get("ativo", True):
            return {"status": "error", "message": "Conta desativada"}

        # is_verified=True como default para não bloquear contas antigas
        if not user.get("is_verified", True):
            return {
                "status":  "error",
                "message": "Email nao verificado. Verifique sua caixa de entrada.",
                "code":    "email_not_verified",
            }

        token = criar_token(user["user_id"], email)
        print(f"[AUTH] Login: {email}")
        return {
            "status": "success",
            "data": {
                "token":     token,
                "user_id":   user["user_id"],
                "nome":      user.get("nome", ""),
                "email":     email,
                "empresa":   user.get("empresa", ""),
                "expira_em": f"{TOKEN_HOURS} horas",
            }
        }
    except Exception as e:
        traceback.print_exc()
        return {"status": "error", "message": f"Erro no login: {str(e)}"}


@app.get("/v2/verify-email")
async def verify_email(token: str):
    """
    Ativa a conta via link enviado por email.
    Após verificar o token, exibe página HTML e redireciona para o frontend.
    """
    if not token:
        return {"status": "error", "message": "Token nao fornecido"}

    db   = get_db()
    user = db.users.find_one({"verify_token": token})

    if not user:
        return {"status": "error", "message": "Link invalido ou ja utilizado"}

    if datetime.utcnow() > user.get("verify_expira", datetime.utcnow()):
        # Remove token expirado mas mantém a conta
        db.users.update_one(
            {"verify_token": token},
            {"$unset": {"verify_token": "", "verify_expira": ""}}
        )
        return {"status": "error", "message": "Link expirado — solicite um novo cadastro"}

    # Ativa conta e remove token (uso único)
    db.users.update_one(
        {"verify_token": token},
        {
            "$set":   {"is_verified": True, "verified_at": datetime.utcnow()},
            "$unset": {"verify_token": "", "verify_expira": ""},
        }
    )
    print(f"[AUTH] Conta verificada: {user['email']}")

    nome = user.get("nome", "")
    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="refresh" content="4;url={FRONTEND_URL}">
  <title>Conta Verificada — MUTY</title>
  <style>
    body {{ font-family:Arial,sans-serif; background:#0a0e17; color:#e2e8f0;
           display:flex; align-items:center; justify-content:center; height:100vh; margin:0; }}
    .box {{ background:#111827; border:1px solid #1f2d42; border-radius:16px;
            padding:40px; text-align:center; max-width:400px; }}
    h1 {{ color:#10b981; font-size:2rem; margin:.5rem 0; }}
    p  {{ color:#94a3b8; line-height:1.6; }}
    a  {{ color:#f59e0b; }}
  </style>
</head>
<body>
  <div class="box">
    <div style="font-size:4rem">&#x2705;</div>
    <h1>Conta Verificada!</h1>
    <p>Ola, <strong style="color:#e2e8f0">{nome}</strong>!</p>
    <p>Sua conta foi ativada com sucesso.<br>Voce sera redirecionado em instantes.</p>
    <p><a href="{FRONTEND_URL}">Clique aqui se nao for redirecionado</a></p>
  </div>
</body>
</html>"""
    return HTMLResponse(content=html)


@app.get("/v2/me")
async def me(user=Depends(get_current_user)):
    """
    Retorna dados do perfil do usuário autenticado.
    BUG CORRIGIDO: projeção explícita exclui senha_hash, _id (ObjectId não é
    serializável em JSON) e tokens temporários de verificação/reset.
    """
    db       = get_db()
    user_doc = db.users.find_one(
        {"user_id": user["user_id"]},
        {"_id": 0, "senha_hash": 0, "verify_token": 0, "verify_expira": 0,
         "reset_token": 0, "reset_expira": 0}
    )
    if not user_doc:
        raise HTTPException(status_code=404, detail="Usuario nao encontrado")
    return {"status": "success", "data": user_doc}


@app.put("/v2/me")
async def atualizar_perfil(request: Request, user=Depends(get_current_user)):
    """
    Atualiza campos do perfil.
    Whitelist de campos — ignora silenciosamente campos não permitidos.
    Limites de tamanho aplicados para evitar abuso.
    """
    try:
        body = await request.json()
        db   = get_db()

        # Nunca incluir email, senha_hash, user_id nesta whitelist
        CAMPOS  = {"nickname", "foto_url", "telefone", "empresa", "nome"}
        LIMITES = {"foto_url": 500_000, "nickname": 30, "nome": 80, "empresa": 80, "telefone": 20}

        update: dict = {}
        for campo in CAMPOS:
            if campo in body and body[campo] is not None:
                valor  = str(body[campo]).strip()
                limite = LIMITES.get(campo, 200)
                if len(valor) > limite:
                    return {"status": "error", "message": f"Campo '{campo}' excede {limite} caracteres"}
                if campo == "telefone":
                    valor = re.sub(r"[^\d\+\(\)\-\s]", "", valor)
                update[campo] = valor

        if not update:
            return {"status": "error", "message": "Nenhum campo valido para atualizar"}

        update["updated_at"] = datetime.utcnow()
        db.users.update_one({"user_id": user["user_id"]}, {"$set": update})

        user_doc = db.users.find_one(
            {"user_id": user["user_id"]},
            {"_id": 0, "senha_hash": 0, "verify_token": 0, "verify_expira": 0,
             "reset_token": 0, "reset_expira": 0}
        )
        print(f"[PERFIL] Atualizado: {user['email']} | campos: {list(update.keys())}")
        return {"status": "success", "data": user_doc}

    except Exception as e:
        traceback.print_exc()
        return {"status": "error", "message": f"Erro: {str(e)}"}


@app.post("/v2/forgot-password")
async def forgot_password(request: Request):
    """
    Solicita redefinição de senha.
    Sempre retorna a mesma mensagem — evita enumeração de usuários.
    """
    MSG = "Se este email estiver cadastrado, voce recebera um link para redefinir a senha."
    try:
        body  = await request.json()
        email = str(body.get("email", "")).strip().lower()

        ok_email, resultado = validar_email_fmt(email)
        if not ok_email:
            return {"status": "error", "message": "Email invalido"}

        db   = get_db()
        user = db.users.find_one({"email": resultado})

        if not user:
            return {"status": "success", "message": MSG}  # não revela que email não existe

        reset_token  = secrets.token_urlsafe(32)
        reset_expira = datetime.utcnow() + timedelta(hours=RESET_HOURS)

        db.users.update_one(
            {"email": resultado},
            {"$set": {"reset_token": reset_token, "reset_expira": reset_expira}}
        )

        enviado = await _email_reset_senha(resultado, user.get("nome", ""), reset_token)
        print(f"[AUTH] Reset solicitado: {resultado} | enviado={enviado}")
        return {"status": "success", "message": MSG}

    except Exception as e:
        traceback.print_exc()
        return {"status": "error", "message": f"Erro: {str(e)}"}


@app.post("/v2/reset-password")
async def reset_password(request: Request):
    """
    Redefine a senha usando o token recebido por email.
    Após uso bem-sucedido, o token é removido do banco (uso único).
    """
    try:
        body       = await request.json()
        token      = str(body.get("token", "")).strip()
        nova_senha = str(body.get("nova_senha", ""))

        if not token:
            return {"status": "error", "message": "Token obrigatorio"}

        ok_senha, msg_senha = validar_senha(nova_senha)
        if not ok_senha:
            return {"status": "error", "message": msg_senha}

        db   = get_db()
        user = db.users.find_one({"reset_token": token})

        if not user:
            return {"status": "error", "message": "Link invalido ou ja utilizado"}

        if datetime.utcnow() > user.get("reset_expira", datetime.utcnow()):
            db.users.update_one(
                {"reset_token": token},
                {"$unset": {"reset_token": "", "reset_expira": ""}}
            )
            return {"status": "error", "message": "Link expirado — solicite novo em /v2/forgot-password"}

        # Atualiza senha e invalida o token (uso único)
        db.users.update_one(
            {"reset_token": token},
            {
                "$set":   {"senha_hash": hash_senha(nova_senha), "updated_at": datetime.utcnow()},
                "$unset": {"reset_token": "", "reset_expira": ""},
            }
        )
        print(f"[AUTH] Senha redefinida: {user['email']}")
        return {"status": "success", "message": "Senha redefinida com sucesso! Faca login com a nova senha."}

    except Exception as e:
        traceback.print_exc()
        return {"status": "error", "message": f"Erro: {str(e)}"}


# ═══════════════════════════════════════════════════════════════════════════════
# SECAO 13.5 — ENDPOINTS V2: PLANO DO USUARIO
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/v2/meu-plano")
async def meu_plano(user=Depends(get_current_user)):
    """
    Retorna o plano atual do usuario, seus beneficios e o perfil.
    Usado pelo frontend para mostrar badge FREE/PLUS e habilitar/desabilitar funcoes.
    """
    db      = get_db()
    user_doc = db.users.find_one(
        {"user_id": user["user_id"]},
        {"plano": 1, "perfil": 1, "plus_desde": 1, "plus_expira": 1}
    )
    plano  = user_doc.get("plano", "free") if user_doc else "free"
    perfil = user_doc.get("perfil", "escolar") if user_doc else "escolar"
    labels = PERFIL_LABELS.get(perfil, PERFIL_LABELS["escolar"])
    is_plus = plano == "plus"

    beneficios_free = [
        "Cadastro de clientes/corridas",
        "Lancamento manual de despesas",
        "Controle de pagamentos",
        "Relatorio mensal",
    ]
    beneficios_plus = [
        *beneficios_free,
        "Sem anuncios",
        "OCR de cupom fiscal (Gemini)",
        "Leitura automatica de NFC-e",
        "Importacao de extrato CSV",
        "Suporte prioritario",
    ]

    return {
        "status": "success",
        "data": {
            "plano":           plano,
            "is_plus":         is_plus,
            "perfil":          perfil,
            "labels":          labels,
            "preco_plus":      PLUS_PRECO_LABEL,
            "beneficios":      beneficios_plus if is_plus else beneficios_free,
            "plus_desde":      user_doc.get("plus_desde")  if user_doc else None,
            "plus_expira":     user_doc.get("plus_expira") if user_doc else None,
            "mp_ativo":        MERCADOPAGO_ACTIVE,
        }
    }


@app.post("/v2/upgrade")
async def upgrade_plano(user=Depends(get_current_user)):
    """
    Gera link de pagamento Mercado Pago para upgrade ao plano Plus.
    Inativo enquanto MERCADOPAGO_ACTIVE=false — retorna mensagem de em breve.
    """
    if not MERCADOPAGO_ACTIVE:
        return {
            "status": "em_breve",
            "message": "Pagamento online em breve! Entre em contato para upgrade manual.",
            "contato": "suporte@trajeto.app",
        }

    if not MERCADOPAGO_TOKEN:
        raise HTTPException(status_code=503, detail="Servico de pagamento nao configurado")

    try:
        import mercadopago
        sdk = mercadopago.SDK(MERCADOPAGO_TOKEN)
        preference_data = {
            "items": [{
                "title":       "Trajeto Plus — Assinatura Mensal",
                "quantity":    1,
                "unit_price":  PLUS_PRECO_CENTAVOS / 100,
                "currency_id": "BRL",
            }],
            "payer":              {"email": user["email"]},
            "external_reference": user["user_id"],
            "back_urls": {
                "success": f"{FRONTEND_URL}?upgrade=ok",
                "failure": f"{FRONTEND_URL}?upgrade=erro",
                "pending": f"{FRONTEND_URL}?upgrade=pendente",
            },
            "auto_return": "approved",
        }
        result = sdk.preference().create(preference_data)
        if result["status"] == 201:
            return {
                "status":   "success",
                "link":     result["response"]["init_point"],
                "link_sandbox": result["response"]["sandbox_init_point"],
            }
        raise HTTPException(status_code=502, detail="Erro ao criar preferencia MP")
    except ImportError:
        raise HTTPException(status_code=503, detail="SDK Mercado Pago nao instalado")
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/v2/webhook/mercadopago")
async def webhook_mercadopago(request: Request):
    """
    Recebe notificacoes de pagamento do Mercado Pago.
    Ao receber pagamento aprovado, ativa o plano Plus do usuario.
    Inativo enquanto MERCADOPAGO_ACTIVE=false.
    """
    if not MERCADOPAGO_ACTIVE:
        return {"status": "inativo"}

    try:
        body    = await request.json()
        tipo    = body.get("type", "")
        data_id = body.get("data", {}).get("id", "")

        if tipo != "payment" or not data_id:
            return {"status": "ignorado"}

        import mercadopago
        sdk     = mercadopago.SDK(MERCADOPAGO_TOKEN)
        payment = sdk.payment().get(data_id)

        if payment["status"] != 200:
            return {"status": "erro_mp"}

        resp    = payment["response"]
        status  = resp.get("status", "")
        user_id = resp.get("external_reference", "")

        if status == "approved" and user_id:
            db = get_db()
            db.users.update_one(
                {"user_id": user_id},
                {"$set": {
                    "plano":       "plus",
                    "plus_desde":  datetime.utcnow(),
                    "plus_expira": datetime.utcnow() + timedelta(days=31),
                    "mp_payment_id": str(data_id),
                }}
            )
            print(f"[MP] Plano Plus ativado: user_id={user_id}")
            return {"status": "ativado"}

        return {"status": f"ignorado ({status})"}
    except Exception as e:
        traceback.print_exc()
        return {"status": "erro", "message": str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
# SECAO 14 — ENDPOINTS V2: DADOS ISOLADOS POR USUARIO
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/v2/todos")
async def v2_get_todos(user=Depends(get_current_user)):
    """Carrega pagamentos + despesas + clientes do usuário autenticado."""
    db  = get_db()
    uid = user["user_id"]
    clientes   = sorted(
        _get_dados(db, uid, "clientes") or [],
        key=lambda c: c.get("nome", "").lower()
    )
    pagamentos = _get_dados(db, uid, "pagamentos") or {}
    despesas   = _get_dados(db, uid, "despesas")   or []
    return {"status": "success", "data": {"pagamentos": pagamentos, "despesas": despesas, "clientes": clientes}}


@app.get("/v2/clientes")
async def v2_get_clientes(user=Depends(get_current_user)):
    dados = _get_dados(get_db(), user["user_id"], "clientes") or []
    return {"status": "success", "data": sorted(dados, key=lambda c: c.get("nome", "").lower())}


@app.put("/v2/clientes")
async def v2_save_clientes(request: Request, user=Depends(get_current_user)):
    dados = await request.json()
    if not isinstance(dados, list):
        return {"status": "error", "message": "Formato invalido — esperado uma lista"}
    dados = sorted(dados, key=lambda c: c.get("nome", "").lower())
    ok = _save_dados(get_db(), user["user_id"], "clientes", dados)
    return {"status": "success" if ok else "error", "data": {"saved": ok}}


@app.get("/v2/pagamentos")
async def v2_get_pagamentos(user=Depends(get_current_user)):
    dados = _get_dados(get_db(), user["user_id"], "pagamentos") or {}
    return {"status": "success", "data": dados}


@app.put("/v2/pagamentos")
async def v2_save_pagamentos(request: Request, user=Depends(get_current_user)):
    dados = await request.json()
    if not isinstance(dados, dict):
        return {"status": "error", "message": "Formato invalido — esperado um objeto"}
    ok = _save_dados(get_db(), user["user_id"], "pagamentos", dados)
    return {"status": "success" if ok else "error", "data": {"saved": ok}}


@app.get("/v2/despesas")
async def v2_get_despesas(user=Depends(get_current_user)):
    dados = _get_dados(get_db(), user["user_id"], "despesas") or []
    return {"status": "success", "data": dados}


@app.put("/v2/despesas")
async def v2_save_despesas(request: Request, user=Depends(get_current_user)):
    dados = await request.json()
    if not isinstance(dados, list):
        return {"status": "error", "message": "Formato invalido — esperado uma lista"}
    ok = _save_dados(get_db(), user["user_id"], "despesas", dados)
    return {"status": "success" if ok else "error", "data": {"saved": ok}}


# ═══════════════════════════════════════════════════════════════════════════════
# SEÇÃO 15 — ENDPOINTS V2: OCR DE CUPOM FISCAL
# Pipeline: QR params → Gemini Vision → Regex local.
# Sempre retorna status:success — campos null ficam editáveis no frontend.
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/v2/ocr")
async def ocr_cupom(
    imagem: UploadFile = File(...),
    qr_url: str        = Form(default=""),
    user:   dict       = Depends(get_current_user),
):
    """
    Extrai dados de um cupom fiscal a partir de uma foto (imagem).
    Requer autenticacao E plano Plus — protege a cota do Gemini.
    Plano Free recebe erro com codigo 'plano_free' para exibir modal de upgrade.

    Pipeline em cascata (ordem de prioridade):
      1. QR params  — extrai valor/data direto da URL do QR Code (gratis, instantaneo)
      2. Gemini OCR — Vision AI analisa a imagem (consome cota da API)
      3. Regex      — fallback local sobre o texto bruto do Gemini

    Resposta: sempre status=success com campos null se nao extraidos.
    O frontend exibe os campos null para edicao manual pelo usuario.

    """
    # Verificacao de plano
    if not _is_plus(get_db(), user["user_id"]):
        return {
            "status":  "error",
            "code":    "plano_free",
            "message": "Funcionalidade exclusiva do plano Plus. Faca upgrade para usar o OCR automatico.",
            "mp_ativo": MERCADOPAGO_ACTIVE,
        }

    # Leitura e validacao da imagem
    try:
        raw  = await imagem.read()
        mime = imagem.content_type or "image/jpeg"
        if not mime.startswith("image/"):
            return {"status": "error", "message": "Arquivo deve ser uma imagem"}
        if len(raw) > 10 * 1024 * 1024:
            return {"status": "error", "message": "Imagem muito grande — maximo 10MB"}
        if len(raw) < 100:
            print("[OCR] AVISO: imagem muito pequena")
        b64 = base64.b64encode(raw).decode()
        print(f"[OCR] Imagem: {len(raw)} bytes | mime: {mime} | qr_url: {bool(qr_url)}")
    except Exception as e:
        return {"status": "error", "message": f"Erro ao ler imagem: {e}"}

    fontes_coletadas: list[tuple[str, dict]] = []

    # Etapa 1: QR params (instantâneo, sem custo)
    if qr_url:
        dados_qr = _qr_extrair(qr_url)
        if any(v is not None for v in dados_qr.values()):
            fontes_coletadas.append(("qr", dados_qr))

    # Etapa 2: Gemini Vision
    chaves = [k for k in [GEMINI_API_KEY, GEMINI_API_KEY2, GEMINI_API_KEY3] if k]
    print(f"[OCR] Chaves Gemini: {len(chaves)}")
    dados_gem, texto_gemini = await _gemini_ocr(b64, mime, chaves)
    if any(v is not None for v in dados_gem.values()):
        fontes_coletadas.append(("gemini", dados_gem))

    # Etapa 3: Regex (fallback local, sem custo)
    dados_rx = _regex_extrair(texto_gemini)
    if any(v is not None for v in dados_rx.values()):
        fontes_coletadas.append(("regex", dados_rx))

    final, fontes_usadas = _mesclar_fontes(fontes_coletadas)
    categoria = _sugerir_categoria(final.get("estabelecimento") or "")
    CONF      = {"qr": 0.8, "gemini": 1.0, "regex": 0.4}
    confianca = max((CONF.get(f, 0) for f in fontes_usadas), default=0.0)

    print(f"[OCR] Resultado: fontes={fontes_usadas} | {final}")
    return {
        "status": "success",
        "data": {
            "estabelecimento": final["estabelecimento"],
            "valor_total":     final["valor_total"],
            "data":            final["data"],
            "categoria":       categoria,
            "fonte":           fontes_usadas[0] if fontes_usadas else "manual",
            "fontes":          fontes_usadas,
            "confianca":       confianca,
        }
    }


# ═══════════════════════════════════════════════════════════════════════════════
# SEÇÃO 16 — ENDPOINTS V2: NOTA FISCAL POR URL DO QR CODE
# Faz scraping do portal SEFAZ usando a URL do QR Code da NFC-e.
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/v2/nota-fiscal")
async def processar_nota_fiscal(
    request: Request,
    user:    dict = Depends(get_current_user),
):
    """
    Recebe a URL do QR Code de uma NFC-e e extrai os dados da nota fiscal
    fazendo scraping do portal da SEFAZ do estado correspondente.

    Requer autenticacao E plano Plus.

    Estrategia anti-bloqueio:
      - Tenta 3 User-Agents diferentes (mobile, Windows, Linux)
      - Verifica HTTP status E conteudo HTML para detectar bloqueios
      - Retorna code=sefaz_blocked quando nao consegue acesso

    Limitacao conhecida: alguns estados (RJ, SP) bloqueiam requests automatizados.
    """
    # Verificacao de plano
    if not _is_plus(get_db(), user["user_id"]):
        return {
            "status":  "error",
            "code":    "plano_free",
            "message": "Leitura automatica de NFC-e exclusiva do plano Plus.",
            "mp_ativo": MERCADOPAGO_ACTIVE,
        }

    try:
        body = await request.json()
        url  = str(body.get("url", "")).strip()

        if not url or not url.startswith("http"):
            return {"status": "error", "message": "URL invalida"}

        estado   = _detectar_estado(url)
        html     = None
        ult_erro = ""

        user_agents = [
            _HEADERS_NF["User-Agent"],
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ]

        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
            for ua in user_agents:
                try:
                    resp = await client.get(url, headers={**_HEADERS_NF, "User-Agent": ua})

                    if resp.status_code in (403, 429, 503):
                        ult_erro = f"Bloqueado (HTTP {resp.status_code})"
                        continue

                    resp.raise_for_status()
                    conteudo = resp.text

                    if len(conteudo) < 500:
                        ult_erro = "Resposta muito curta"
                        continue

                    termos_bloqueio = ["acesso bloqueado", "acesso negado", "access denied",
                                       "403 forbidden", "captcha", "bot detection"]
                    if any(t in conteudo.lower() for t in termos_bloqueio):
                        ult_erro = "Portal retornou pagina de bloqueio"
                        continue

                    html = conteudo
                    break

                except httpx.TimeoutException:
                    ult_erro = "Timeout"
                    continue
                except httpx.HTTPStatusError as e:
                    ult_erro = f"HTTP {e.response.status_code}"
                    continue
                except Exception as e:
                    ult_erro = str(e)
                    continue

        if html is None:
            return {
                "status":  "error",
                "message": f"Portal SEFAZ bloqueou o acesso ({ult_erro}). Use o modo manual ou tire foto.",
                "code":    "sefaz_blocked",
            }

        estabelecimento = _nf_extrair_estabelecimento(html)
        return {
            "status": "success",
            "data": {
                "estabelecimento": estabelecimento,
                "valor":           _nf_extrair_valor(html),
                "data":            _nf_extrair_data(html),
                "categoria":       _sugerir_categoria(estabelecimento),
                "estado":          estado,
            }
        }

    except Exception as e:
        traceback.print_exc()
        return {"status": "error", "message": f"Erro interno: {str(e)}"}


# ==============================================================================
# SECAO 17 — ENDPOINTS V2: DIAGNOSTICO
# CORRIGIDO: todos protegidos por JWT — nunca expor sem autenticacao.
# Usar apenas em desenvolvimento ou suporte tecnico autenticado.
# ==============================================================================

@app.get("/v2/debug-ocr")
async def debug_ocr(user=Depends(get_current_user)):
    """
    Verifica quais chaves Gemini estao configuradas no ambiente.
    Exibe apenas prefixo e sufixo — nunca a chave completa.
    CORRIGIDO: protegido por JWT para evitar exposicao de info de configuracao.
    """
    def _preview(k: str) -> str:
        return f"{k[:8]}...{k[-4:]}" if k else "NAO_CONFIGURADA"

    chaves = [k for k in [GEMINI_API_KEY, GEMINI_API_KEY2, GEMINI_API_KEY3] if k]
    return {
        "status":           "ok",
        "total_chaves":     len(chaves),
        "GEMINI_API_KEY":   _preview(GEMINI_API_KEY),
        "GEMINI_API_KEY_2": _preview(GEMINI_API_KEY2),
        "GEMINI_API_KEY_3": _preview(GEMINI_API_KEY3),
        "aviso":            None if chaves else "Nenhuma chave Gemini configurada!",
    }


@app.get("/v2/debug-email")
async def debug_email(user=Depends(get_current_user)):
    """
    Verifica se as configuracoes de email estao presentes.
    CORRIGIDO: protegido por JWT.
    """
    return {
        "status":            "ok",
        "resend_api_key":    "configurada" if RESEND_API_KEY else "NAO_CONFIGURADA",
        "resend_key_prefix": RESEND_API_KEY[:8] + "..." if RESEND_API_KEY else "—",
        "provedor":          "Resend API (HTTPS porta 443)",
    }


@app.post("/v2/test-email")
async def test_email(request: Request, user=Depends(get_current_user)):
    """
    Envia email de teste para diagnostico.
    CORRIGIDO: protegido por JWT — evita spam via endpoint aberto.
    """
    try:
        body = await request.json()
        para = str(body.get("email", "")).strip()
        if not para:
            return {"status": "error", "message": "Email obrigatorio"}
        ok = await enviar_email(
            destino = para,
            assunto = "Teste Trajeto — Email funcionando",
            html    = "<h2>Trajeto SaaS</h2><p>Email de teste enviado com sucesso via Resend!</p>",
        )
        return {"status": "success" if ok else "error", "enviado": ok, "para": para}
    except Exception as e:
        return {"status": "error", "message": str(e)}
