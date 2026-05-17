# PROJETO RDS — Especificação

## Resumo

PROJETO RDS consiste num controlador com vários plugins. Um plugin central será o `CNF Control`, responsável por gerir e recolher telemetria de CNFs (Containerized Network Functions) que expõem uma API (REST ou gRPC). Inicialmente a comunicação será em `localhost` entre containers e controlador.

## Objetivo

- Permitir ao controlador descobrir, comunicar e configurar CNFs através de uma API comum.
- Recolher telemetria básica para observabilidade e monitorização.
- Fornecer operações de configuração (por exemplo: pool de IPs, gateway, ficheiro ARP).

## Escopo inicial

- Suportar dois CNFs de exemplo: `arp_proxy` e `dhcp_server` (existentes em `cNF/`).
- Ignorar, por agora, comunicação directa com o dispositivo P4; foco em comunicação via localhost.

## Requisitos Funcionais

1. Cada CNF deverá expor uma API REST mínima com endpoints para:
   - `/telemetry` — retornar métricas e estados actuais.
   - `/health` — estado de saúde (OK/NOT_OK).
   - `/config` — aceitar alterações de configuração (GET/PUT POST conforme necessário).
2. O plugin `CNF Control` no controlador deverá poder:
   - Descobrir CNFs registados (config manual ou descoberta simples).
   - Pedir telemetria periódica (pull) ou subscrever notificações (opcional).
   - Aplicar configurações via `/config`.

## Requisitos Não-Funcionais

- Comunicação local via HTTP/JSON (simples e interoperável).
- Documentação mínima da API e payloads.
- Simplicidade: implementar com poucas dependências para facilitar testes locais.

## Telemetria por CNF (detalhe)

- DHCP (`dhcp_server`):
  - Número total de comunicações / requisições DHCP.
  - Número de IPs actualmente atribuídos.
  - Lista de IPs activos (com timestamps de atribuição).
  - Configurações: pool de IPs, gateway, DNS.
- ARP (`arp_proxy`):
  - Número de pedidos ARP recebidos.
  - Tempo médio de resposta ARP (ms).
  - Ficheiro/mapeamento ARP configurável (possibilidade de upload/refresh).

## API REST mínima (exemplo de payloads)

- GET `/telemetry`
  - Resposta (DHCP): `{ "requests": 123, "leased_ips": 10, "ips": ["10.0.0.2", ...] }`
  - Resposta (ARP): `{ "requests": 456, "avg_response_ms": 12.3 }`
- GET `/health` -> `{ "status": "OK" }`
- GET `/config` -> retorna configuração actual
- PUT `/config` com JSON -> aplica nova configuração

## Implementação — Passos técnicos

1. Definir e documentar a especificação da API (endpoints, schemas JSON).
2. Implementar endpoints REST em `cNF/arp_proxy` e `cNF/dhcp_server` que exponham telemetria e permitam configuração.
3. Implementar plugin `CNF Control` em `controller/plugins/` para:
   - Ler lista de CNFs (config file ou descoberta).
   - Periodicamente recolher `/telemetry` e expor ao controlador (logs, endpoint ou DB leve).
   - Aplicar configurações via `/config`.
4. Testar localmente com containers: levantar `dhcp_server` e `arp_proxy` e validar chamadas HTTP.
5. Medir e documentar limitações de escala (simular N instâncias, medir latência e uso de CPU/memória).

## Testes e validação

- Testes unitários para adaptadores de API (simular respostas JSON).
- Testes integrados: levantar ambos os CNFs e o controlador, validar fluxo completo (telemetria + config).
- Testes de carga simples para avaliar capacidade de recolha de telemetria a escala.

## Escalabilidade e limitações a estudar

- Overhead do controlador ao agregar telemetria de muitos CNFs.
- Eficiência do formato pull vs push para telemetria.
- Bottlenecks em JSON/HTTP vs gRPC (se necessário migrar mais tarde).

## Próximos passos recomendados

1. Aceitar esta especificação como base.
2. Escolher entre REST (rápido a implementar) ou gRPC (mais eficiente a escala).
3. Implementar endpoints mínimos nos CNFs e validar localmente.
4. Implementar `CNF Control` básico que recolhe `/telemetry` e aplica `/config`.

---
Arquivo gerado automaticamente a pedido do utilizador.
