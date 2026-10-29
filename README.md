# Cyclades

[Version française](README.fr.md)

An end-to-end encrypted messenger that keeps working when the mobile network is down.

> **Prototype under test. Do not use it at a protest.**
> The cryptography has not yet been audited by independent experts.
> Until it is, Cyclades protects no one.

## Why this name

In the early 1970s, Louis Pouzin and his team at IRIA, in France, built Cyclades, one of the first packet-switched networks. Their idea: a network that only carries packets, and machines at the edges that do the rest. That idea would go on to inspire TCP/IP. In France, the project was dropped at the end of the decade in favour of Transpac, the national telecom operator's network, which would later carry the Minitel.

This Cyclades starts from the same idea: the middle only carries, and everything else happens at the edges. It takes it one step further: whoever relays a message cannot even read it.

## What it does

Phones talk to each other directly over Bluetooth Low Energy and pass messages along from one to the next. No cell tower, Wi-Fi or internet is needed. When the internet is available, a relay can carry messages further. It only sees encrypted envelopes and knows no accounts or names. It does see the IP addresses that connect to it. The relay is optional: without it, everything goes over Bluetooth.

- No account, no phone number, no email address.
- Contacts are added face to face, by scanning a QR code and then comparing a six-digit code.
- Small groups, up to 50 people.
- Text only.

Cyclades is designed first for protests and network shutdowns.

## Project status

- The protocol, mesh and cryptography specifications are written and under review.
- The mesh engine runs in simulation, with several hundred virtual phones.
- The Bluetooth layer is being tested on real devices (iPhone, iPad and Android) while they are locked, in the background and overnight.
- The client-side cryptography is not coded yet. It will only be coded after an external review.

The code will be published here as it matures.

## Transparency

Design, technical decisions and all testing on real devices: me.
The documentation and part of the code are written with the help of an AI assistant (Claude), then reviewed, tested and validated by me. The cryptographic test vectors are recomputed by independent implementations.

## Security

Found a vulnerability, or have a doubt? Report it privately via the Security tab → Report a vulnerability.
Please do not open a public issue for a security vulnerability.

## Licence

[AGPL-3.0](LICENSE). If you modify Cyclades and distribute it, or run it as a service, you must publish your source code.
