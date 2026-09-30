# Contoso Shop Floor Operations MCP Server

Tools for agents that answer questions about live manufacturing operations: open work
orders, machine status and shift handover notes.

## Tools

| Tool | What it does |
|---|---|
| `list_open_work_orders` | Open work orders for a production line, newest first |
| `get_machine_status` | Status, last heartbeat and active downtime reason for a machine |
| `record_shift_handover` | Writes a handover note against a production line |

## Setup

1. Request a service account from your Contoso administrator.
2. Register the MCP server URL for your plant: `https://mcp.contoso.com/shopfloor`.
3. Grant the agent the `ShopFloor.Read` scope, and `ShopFloor.Write` only if you intend
   to use `record_shift_handover`.

## Authentication

OAuth2 authorization code flow. The certification package supplies the client
configuration through Azure Key Vault; nothing is embedded in the manifest.

## Known issues and limitations

- `get_machine_status` reports the last heartbeat, which can trail live state by up to
  30 seconds on lines using the legacy PLC gateway.
- `record_shift_handover` is rejected outside a shift boundary window of 30 minutes
  either side of the scheduled change. Callers get a `409` with an explanatory body.
- Historical work orders older than 18 months are archived and not visible to
  `list_open_work_orders`. Use the reporting warehouse for those.

## Support

mcp-support@contoso.com
