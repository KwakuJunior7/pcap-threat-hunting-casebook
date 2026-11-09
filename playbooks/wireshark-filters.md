# Wireshark display-filter cheat sheet

These are the filters I actually used in the cases in this repo, grouped by the question each one answers.

## Who is on the network?

| Filter | What it shows | Used in |
|---|---|---|
| `nbns` | NetBIOS name registrations, e.g. `Registration NB DESKTOP-XXXX<00>` = Windows hostname | Case 01, 02 |
| `dns` + **Name** column | Query names. Look for `Dynamic update` (opcode 5): a host registering its own A record | Case 01, 02 |
| `dns.qry.name` | Every packet that has a DNS/LLMNR/mDNS query name | Case 01, 02 |
| `dhcp` (`bootp` in old versions) | Option 12 = hostname, option 50 = requested IP, client MAC | — |
| `smb \|\| nbns \|\| dcerpc \|\| nbss \|\| dns` | One combined Windows "identity" view: names, sessions, DC traffic | Case 01, 02 |
| `ip.addr == 172.16.1.66` | Everything to/from one host. The status bar count shows how much of the capture it is | Case 02 |
| `tcp.flags.syn == 1 && tcp.flags.ack == 1` | SYN/ACKs show which hosts servers accepted connections from (client IP + MAC) | Case 01, 02 |

## Who is logged in?

| Filter | What it shows |
|---|---|
| `kerberos` | Expand `req-body → cname → CNameString` in **AS-REQ** = the user logging in. Accounts ending in `$` are machine accounts |
| `kerberos.CNameString and !(kerberos.CNameString contains "$")` | Only human user accounts |
| `ldap.AttributeDescription == "givenName"` | LDAP lookups of the user's own object. `baseObject: CN=First Last,...` gives the full name |
| `ldap.AttributeDescription == "serverName"` | rootDSE queries, i.e. a client discovering the domain |
| `smb2` → Session Setup / Logoff | Wireshark annotates `Acct: user Domain: X Host: Y` |

## What left the network?

| Filter | What it shows |
|---|---|
| `http.request` | All HTTP requests. Check **Host** (raw IP?), **User-Agent** (missing?), **URI** (random filename?) |
| `(http.request or tls.handshake.type eq 1 or (tcp.flags.syn eq 1 and tcp.flags.ack eq 0)) and !(ssdp)` | A "web traffic" view: HTTP + TLS Client Hellos (SNI) + outbound connection attempts |
| `tls.handshake.extensions_server_name` | HTTPS destinations by name, even though the content is encrypted |
| `tcp.port == 80 \|\| udp.port == 80` | Full plaintext web conversations, including responses |
| `tcp.stream eq N` | One conversation. Right-click → *Follow → TCP Stream* to read it |
| `llmnr` / `udp.port == 5355` | LLMNR queries, which can be spoofed by an attacker on the LAN |

## Workflow tips
* Add **Host**, **Name** (dns.qry.name), and **Destination Port** as custom columns.
* Use *Statistics → Conversations* and *Statistics → Endpoints* first to see who talks the most.
* Use *File → Export Objects → HTTP* to pull downloaded files. **Only do this inside an isolated VM**, then hash the files (`sha256sum`).
* Write down frame numbers and relative times as you go. The timeline writes itself.
