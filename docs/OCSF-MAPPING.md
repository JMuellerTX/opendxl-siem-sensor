# OCSF Mapping: OpenDXL SIEM Sensor

Dieses Dokument beschreibt die Zuordnung von OpenDXL-Ereignissen auf das Open Cybersecurity Schema Framework (OCSF) in der Version 1.x. Der Sensor normalisiert Rohereignisse aus dem DXL-Protokoll in standardisierte OCSF-Klassen, um eine nahtlose Integration in moderne SIEM-Lösungen zu gewährleisten.

## Mapping-Zusammenfassung

Alle ausgegebenen Events teilen sich gemeinsame OCSF-Pflichtattribute wie `time`, `severity_id`, `severity`, und `metadata` (`metadata.product.name = "Rust SIEM Sensor"`, `metadata.product.vendor_name = "OpenDXL"`).

| DXL Event | OCSF Class | Class UID | Activity | Activity ID | Type UID |
|-----------|------------|-----------|----------|-------------|----------|
| `clientregistry/connect` | Network Activity | 4001 | Connect | 1 | 400101 |
| `clientregistry/disconnect` | Network Activity | 4001 | Disconnect | 2 | 400102 |
| `svcregistry/register` | API Activity | 6003 | Create | 1 | 600301 |
| `svcregistry/unregister` | API Activity | 6003 | Delete | 4 | 600304 |
| Synthetische Alarme | Detection Finding | 2004 | Create | 1 | 200401 |

## 1. Network Activity (Class UID: 4001)

Verwendet für Verbindungsaufbauten und -abbrüche von Clients am Broker (`clientregistry/connect`, `clientregistry/disconnect`).

**Begründung der Klassenwahl:**
Connect- und Disconnect-Events repräsentieren den Aufbau und Abbau von TCP/TLS-Verbindungen zum MQTT-Broker. Die `Network Activity`-Klasse deckt diese Art von Netzwerkverkehr ab und bietet dedizierte Attribute für Transport- und Verschlüsselungsdetails.

**Relevante OCSF-Attribute:**
*   `activity_id`: `1` (Connect), `2` (Disconnect)
*   `client_guid` (Custom Field): Der DXL Client-Instance-GUID.
*   `connection_info.protocol_name`: `mqtt` oder `websocket` (falls vom Broker gemeldet).
*   `src_endpoint.ip`: Die IP-Adresse des anfragenden Clients (IPv4-mapped Adressen werden bereinigt).
*   `tls.version`: Aushandlungsergebnis der TLS-Verbindung (z.B. `TLSv1.3`).
*   `tls.cipher_suites`: Die ausgehandelte IANA-Cipher (z.B. `TLS_AES_256_GCM_SHA384`).
*   `tls.certificate.fingerprint`: Der SHA-1 Thumbprint des Client-Zertifikats.

## 2. API Activity (Class UID: 6003)

Verwendet für das Registrieren und Deregistrieren von OpenDXL-Diensten (`svcregistry/register`, `svcregistry/unregister`).

**Begründung der Klassenwahl:**
Das Registrieren eines Services in der DXL-Fabric ähnelt stark einem API-Aufruf zur Ressourcenerstellung, bzw. beim Unregister dem Löschen der Ressource. "API Activity" repräsentiert Interaktionen mit Services und deren Lebenszyklus-Methoden (Create/Delete) sehr gut, während "Application Lifecycle" eher den Zustand lokaler Anwendungen beschreibt.

**Relevante OCSF-Attribute:**
*   `activity_id`: `1` (Create) für `register`, `4` (Delete) für `unregister`.
*   `api.service.uid`: Die eindeutige `serviceGuid` des Dienstes.
*   `api.service.name`: Der Name bzw. Typ des Dienstes (`serviceType`, z.B. `/mcafee/service/tie/file/reputation`).
*   `actor.user.uid`: Der SHA-1 Thumbprint des registrierenden Dienst-Clients (sofern im Register-Event übertragen).

## 3. Detection Finding (Class UID: 2004)

Verwendet für alle vom Sensor selbst generierten Anomalien (Detections).

**Begründung der Klassenwahl:**
Der Sensor fungiert hierbei selbst als Security-Analytics-Komponente. Synthetische Alarme wie "Unknown Thumbprint" oder "Legacy Cipher Suite" stellen konkrete Sicherheitsbefunde dar, für die die `Detection Finding`-Klasse vorgesehen ist.

**Relevante OCSF-Attribute:**
*   `activity_id`: `1` (Create)
*   `finding_info.title`: Name der Detection (z.B. "Legacy Cipher Suite").
*   `finding_info.desc`: Beschreibung und Kontext des Alarms.
*   `suser`: Optional, enthält den Zertifikats-Thumbprint des beteiligten Clients.
*   `severity_id`: Standardmäßig `4` (High).
