# DIEGO - Domain Intranet Elusive Guardian & Offensive-Scouter

Agente de diagnóstico de seguridad Active Directory sin privilegios, escrito en Rust puro.

---

**DIEGO** es un agente de reconocimiento posterior a la explotación y diagnóstico de seguridad para entornos de Active Directory. Opera completamente con credenciales estándar de usuario de dominio, no produce artefactos de red ruidosos y se distribuye como un único binario estático.

## Pilares Clave

- **Sin Privilegios** — Funciona solo con credenciales estándar de usuario de dominio. No se requieren derechos de administrador en ningún momento.
- **Sigilo (Compatible con OPSEC)** — Solo emite consultas AD legítimas. Sin escaneo agresivo. La fluctuación configurable entre solicitudes se mezcla con el tráfico normal del dominio.
- **Portátil** — Un único binario estático sin dependencias de tiempo de ejecución. Coloca y ejecuta en cualquier host objetivo.
- **Rust Puro** — Sin CLR de .NET, sin PowerShell, sin intérprete de Python. Cada interacción de protocolo — encuadre ASN.1 de Kerberos, LDAP, RC4-HMAC — se implementa en Rust puro (RustCrypto). Esto elimina la superficie de ataque ETW / AMSI / Script Block Logging que los productos EDR monitorean más agresivamente.
- **Primero en IA** — La integración de API de Claude sintetiza la salida de análisis en una narrativa de ataque coherente. El modo servidor MCP permite que los clientes LLM orquesten herramientas de diagnóstico individuales directamente.

---

## Inicio Rápido

```bash
# Modo CLI — ejecutar todos los módulos de diagnóstico
# La contraseña se puede omitir; diego intentará: variable env → keytab → caché TGT → solicitud interactiva
diego --dc 10.0.0.1 --domain corp.local --username jdoe

# Con contraseña explícita (menos seguro; evita el historial de shell con variable env en su lugar)
diego --dc 10.0.0.1 --domain corp.local --username jdoe --password P@ss

# Con análisis de IA (requiere ANTHROPIC_API_KEY)
diego --dc 10.0.0.1 --domain corp.local --username jdoe --ai-analyze

# Chat de IA interactivo después del análisis
diego ... --ai-analyze --chat

# Modo servidor MCP (para Claude Desktop / clientes MCP)
diego --mcp
```

---

## Licencia

MIT
