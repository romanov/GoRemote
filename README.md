# FreeBSD Pilot

<img width="450" height="150" alt="logo" src="https://github.com/user-attachments/assets/0121a617-4ba6-4ace-841d-5d4ff38e8ef5" />

FreeBSD Pilot is a small, dependency-free FreeBSD web command console. It serves a
chat-style page on port 8080, runs each submitted command with `/bin/sh -c`, and
streams stdout and stderr back as newline-delimited JSON.

> [!CAUTION]
> This application intentionally provides unauthenticated remote command
> execution. When the service runs as root, every client admitted by the
> network firewall and the application's IP allowlist has unrestricted root
> access. Do not start it until the firewall allowlist is loaded and verified.
> Plain HTTP does not encrypt commands or output.

## Build

On FreeBSD:

```sh
go test ./...
go build -trimpath -o goremote .
```

Cross-compile for FreeBSD amd64 or arm64:

```sh
env GOOS=freebsd GOARCH=amd64 go build -trimpath -o goremote-freebsd-amd64 .
env GOOS=freebsd GOARCH=arm64 go build -trimpath -o goremote-freebsd-arm64 .
```

The target FreeBSD machine needs only the resulting binary. Go is not required
at runtime.

## Firewall

Add rules like these to `/etc/pf.conf`, replacing the interface and example
addresses. The first quick rule admits allowlisted clients; the second quick
rule rejects everyone else even if a broader pass rule appears later.

```pf
ext_if = "em0"
table <goremote_clients> const { 192.0.2.10, 198.51.100.20 }

pass in quick on $ext_if inet proto tcp from <goremote_clients> to ($ext_if) port 8080 flags S/SA keep state
block in quick on $ext_if inet proto tcp from any to ($ext_if) port 8080
```

Validate before loading the rules:

```sh
pfctl -nf /etc/pf.conf
sysrc pf_enable=YES
service pf start
pfctl -f /etc/pf.conf
pfctl -sr
```

Keep an existing administrative session open while changing a remote
machine's firewall, and verify that a non-allowlisted host cannot connect.

## Install as a FreeBSD service

After the firewall is active:

```sh
install -o root -g wheel -m 0555 goremote /usr/local/sbin/goremote
install -o root -g wheel -m 0555 freebsd/goremote /usr/local/etc/rc.d/goremote
sysrc goremote_enable=YES
sysrc goremote_listen="0.0.0.0:8080"
sysrc goremote_timeout="10m"
sysrc goremote_allowlist_file="/var/db/goremote/allowed-ips.json"
service goremote start
```

The service script refuses to start while `pf` is disabled and forwards the
application's stdout and stderr to syslog with the `goremote` tag.

Open `http://SERVER_IP:8080/` from an allowlisted address. View service output
in the system log using `grep goremote /var/log/messages`.

## Web IP allowlist

Open `http://SERVER_IP:8080/settings` to manage the application's HTTP
allowlist. Enter one exact IPv4 or IPv6 address per line and save it. Once the
list contains an address, every request from another TCP peer address receives
HTTP 403, including requests to the settings page. Any allowlisted address can
view and change the list.

The list is stored as a JSON array in
`/var/db/goremote/allowed-ips.json` by default. The parent directory is created
when the first save occurs, and the service account must be able to write it.
If the file is missing or the saved list is empty, IP enforcement is disabled
so the service can be configured. Invalid or unreadable files prevent startup.
Requests behind a reverse proxy are checked using the proxy's TCP address;
`X-Forwarded-For` is not trusted.

The service runs as root because the rc script does not set `command_user`.
For a safer deployment, set `goremote_user` through a customized rc script and
grant only the filesystem and service permissions that account needs.

## Runtime options

```text
-listen string
      HTTP listen address (default "0.0.0.0:8080")
-timeout duration
      maximum runtime for each command (default 10m0s)
-allowlist-file string
      JSON file containing allowed client IP addresses
      (default "/var/db/goremote/allowed-ips.json")
```

Each request starts a fresh shell, so `cd`, shell variables, aliases, and other
state do not carry to the next request. The Stop button aborts the HTTP request;
on FreeBSD the server kills the command's entire process group. Closing or
reloading the page has the same effect. Interactive TTY programs and additional
stdin after submission are not supported.

## HTTP API

Read the current allowlist with `GET /api/allowlist` or replace it with a
same-origin JSON request to `POST /api/allowlist`:

```sh
curl -X POST \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://SERVER_IP:8080' \
  --data '{"addresses":["192.0.2.10","2001:db8::10"]}' \
  http://SERVER_IP:8080/api/allowlist
```

Submit one JSON object:

```sh
curl -N \
  -H 'Content-Type: application/json' \
  --data '{"command":"service nginx status"}' \
  http://SERVER_IP:8080/api/commands
```

The response uses `application/x-ndjson`. Events have these shapes:

```json
{"type":"started","id":"1"}
{"type":"stdout","data":"nginx is running as pid 1234.\n"}
{"type":"stderr","data":"warning text\n"}
{"type":"exited","exit_code":0,"duration_ms":42}
```

Timed-out and canceled exit events add `timed_out: true` or `canceled: true`.
The request body is limited to 16 KiB. Commands and output are never persisted,
and command text is not written to the service log.
