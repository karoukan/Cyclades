# Cyclades

[English version](README.md)

Une messagerie chiffrée de bout en bout qui continue de fonctionner quand le réseau mobile est coupé.

> **Prototype en cours de test. Ne l'utilisez pas en manifestation.**
> La cryptographie n'a pas encore été auditée par des experts indépendants.
> Tant que ce n'est pas fait, Cyclades ne protège personne.

## Pourquoi ce nom

Au début des années 1970, Louis Pouzin et son équipe de l'IRIA construisent Cyclades, l'un des premiers réseaux à commutation de paquets. Leur idée : un réseau qui se contente de transporter des paquets, et des machines aux extrémités qui font le reste. Cette idée inspirera TCP/IP. En France, le projet est abandonné à la fin de la décennie au profit de Transpac, le réseau des PTT, sur lequel tournera le Minitel.

Ce Cyclades-ci part de la même idée : au milieu, on se contente de transporter, et tout le reste se fait aux extrémités. Il la pousse un cran plus loin : ceux qui relaient un message ne peuvent même pas le lire.

## Ce que ça fait

Les téléphones se parlent directement en Bluetooth basse consommation et se relaient les messages de proche en proche. Ça marche sans antenne, sans Wi-Fi et sans internet. Quand internet est disponible, un relais peut transmettre les messages plus loin. Il ne voit que des enveloppes chiffrées et ne connaît aucun compte ni aucun nom. Il voit en revanche les adresses IP qui s'y connectent. Le relais est facultatif : sans lui, tout passe par le Bluetooth.

- Pas de compte, pas de numéro de téléphone, pas d'adresse e-mail.
- On ajoute un contact en face à face, en scannant un QR code puis en comparant un code à six chiffres.
- Petits groupes, jusqu'à 50 personnes.
- Texte uniquement.

Cyclades est pensé d'abord pour les manifestations et les coupures de réseau.

## Où en est le projet

- Les spécifications du protocole, du maillage et de la cryptographie sont écrites et en cours de relecture.
- Le moteur de maillage tourne en simulation, avec plusieurs centaines de téléphones virtuels.
- La couche Bluetooth est testée sur de vrais appareils, iPhone, iPad et Android, verrouillés, en arrière-plan, la nuit.
- La cryptographie côté application n'est pas encore codée. Elle ne le sera qu'après une relecture externe.

Le code sera publié ici au fur et à mesure.

## Transparence

Conception, choix techniques et tests sur de vrais appareils : moi.
Le code (en partie) et la documentation sont écrits avec l'aide d'un assistant IA (Claude), puis relus, testés et validés par moi. Les vecteurs de test cryptographiques sont recalculés par des implémentations indépendantes.

## Sécurité

Une faille, un doute ? Signalez-la en privé via l'onglet Security → Report a vulnerability.
Merci de ne pas ouvrir de ticket public pour une faille de sécurité.

## Licence

[AGPL-3.0](LICENSE). Si vous modifiez Cyclades et le distribuez, ou le faites tourner comme service, vous devez publier vos sources.

Les spécifications dans docs/ sont sous CC BY-SA 4.0.
