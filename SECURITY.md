# Security Policy

*[Version française plus bas](#politique-de-sécurité).*

Katakomba runs as root and handles VPN credentials: security reports are taken seriously.

## Supported versions

Only the latest release receives fixes.

| Version | Supported |
|---------|-----------|
| 3.8.x   | ✅ |
| < 3.8   | ❌ |

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private reporting instead:
**[Security → Report a vulnerability](https://github.com/Derbosoft/Katakomba/security/advisories/new)**.

Please include:
- the Katakomba version (`katakomba status`) and distribution;
- the steps to reproduce, or a proof of concept;
- the impact as you understand it (privilege escalation, traffic leak outside the tunnel, credential exposure…).

Strip your VPN credentials, real IP addresses and provider `.ovpn` files from anything you send.

## Scope

Especially relevant:
- a path for a `katakomba` group member, or any unprivileged user, to run code as root;
- traffic or DNS queries leaving outside the tunnel while it is reported as up;
- an `.ovpn` or torrc directive that bypasses the allowlists (`validation.py`);
- credentials written to the journal, the status socket or a world-readable file.

Out of scope: the known, documented limits (the kill switch is lifted while the service is stopped or being relaunched after a crash, base64 obfuscation of credentials in `config.json`). See the [Security section of the README](README.md#security).

---

# Politique de sécurité

Katakomba tourne en root et manipule des identifiants VPN : les signalements de sécurité sont traités en priorité.

**N'ouvrez pas d'issue publique.** Utilisez le signalement privé de GitHub :
**[Security → Report a vulnerability](https://github.com/Derbosoft/Katakomba/security/advisories/new)**.

Indiquez la version (`katakomba status`), la distribution, les étapes pour reproduire et l'impact. Retirez vos identifiants VPN, vos adresses IP réelles et les fichiers `.ovpn` de votre fournisseur.

Seule la dernière version reçoit des correctifs. Les limites connues et documentées (blocage hors tunnel levé quand le service est arrêté ou en cours de relance après un plantage, identifiants en base64 dans `config.json`) ne sont pas des vulnérabilités : voir la section [Sécurité du README](README.fr.md#sécurité).
