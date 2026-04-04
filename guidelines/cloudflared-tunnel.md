# Cloudflared Tunnel Setup For InfiniMii

This server is prepared for a remotely-managed Cloudflare Tunnel.

## Server-side pieces already in place

- `cloudflared` is installed from Cloudflare's official Ubuntu repository.
- A `systemd` unit exists at `/etc/systemd/system/cloudflared.service`.
- Tunnel tokens are read from `/etc/cloudflared/tunnel-token`.
- Logs go to `/var/log/cloudflared/cloudflared.log`.
- Metrics bind to `127.0.0.1:20241`.

## What to create in Cloudflare

1. In the Cloudflare dashboard, go to `Networking > Tunnels`.
2. Create a tunnel for this server.
3. Choose the Linux connector type.
4. Copy the connector token.
5. In that tunnel, add published application routes:
   - `infinimii.com` -> `http://127.0.0.1:8080`
   - `www.infinimii.com` -> `http://127.0.0.1:8080`

Cloudflare will create the DNS records for those hostnames when you add the routes in the dashboard.

## How to install the token on the server

```bash
sudo /usr/local/bin/cloudflared-install-token 'PASTE_TUNNEL_TOKEN_HERE'
```

## Useful commands

```bash
systemctl status cloudflared
journalctl -u cloudflared -n 100 --no-pager
tail -f /var/log/cloudflared/cloudflared.log
```
