- [Vermouth](#vermouth)
- [Background](#background)
  * [Why this matters](#why-this-matters)
  * [Who needs to implement STIR/SHAKEN](#who-needs-to-implement-stir-shaken)
- [Motivation](#motivation)
- [Requirements](#requirements)
  * [Business Requirements](#business-requirements)
  * [Technical Requirements](#technical-requirements)
- [Core Frameworks and Dependencies](#core-frameworks-and-dependencies)
- [Features](#features)
- [Example Operation (In-Spec)](#example-operation--in-spec-)
  * [Signing Request](#signing-request)
  * [Verification Request](#verification-request)
- [Example Operation (Quick Version)](#example-operation--quick-version-)
  * [Signing Request](#signing-request-1)
  * [Verification Request](#verification-request-1)
- [Installation/Setup](#installation-setup)
  * [RPM-based](#rpm-based)
    + [RHEL6](#rhel6)
    + [RHEL7+](#rhel7)
    + [Ubuntu Server LTS 16+](#ubuntu-server-lts-16)
  * [Manual Execution](#manual-execution)
  * [Disclosure of Telemetry](#disclosure-of-telemetry)
  * [Config Example](#config-example)
## Vermouth
This project implements a Centralized Signing and Signature Validation Server for STIR/SHAKEN confirming to the various
ATIS standards. More information can be found at [https://www.fcc.gov/call-authentication](https://www.fcc.gov/call-authentication).
## Background
The year is 2021, the vast majority of folks no longer answer voice calls because the expectation is that the answered
call will be either SPAM or fraud-related. The US government (FCC) as well as legitimate voice service
providers recognize the problem as tens of thousands of complaints roll through.

Historically, shady telecom companies could allow inexpensive, unfettered access to any number of targets primarily
via robocalling. Realistically, it was difficult to ascertain the providence of these calls as so many
of the callers/facilitators are operating abroad. Enter STIR/SHAKEN...

STIR/SHAKEN is an attempt to address the robocalling problem. Rather than directly
intervene in what many worried would become a severe overreach by the federal government, the FCC called on the telecom
industry to perform a self-policing of sorts through **reputation** and **attestation**.

When a call is received by the last-mile carrier, STIR/SHAKEN guarantees that at least the telco that originated the
call (sent into the public telephony network) must be known. In addition, there is an attempt to identify the caller with an A,B, or C
attestation level. This README won't attempt to explain everything about STIR/SHAKEN, but in short: A=This caller is
known to their phone company and is allowed to represent this CID, B=This caller is known to their phone company, but it
is not known whether they can represent this CID,C=This caller is unknown.
### Why this matters
The shady telcos mentioned earlier are no longer able to fly under the radar. They are either a known entity themselves
or can easily be traced back to one. Over time, these telcos, regardless of individual attestation levels, will have
their calls screened and often rejected. As for good-guy telcos with "C" level attestations, the FCC will allow those calls
to be rejected or sent to voice mail.
### Who needs to implement STIR/SHAKEN
All interconnected telecom providers are required to adhere to the standards set forth by the FCC and the ATIS standards
for STIR/SHAKEN.  Some large companies and corporations may also choose to begin signing their own calls, but this is an
evolving manner.
## Motivation
Implementing STIR/SHAKEN is complicated. Obvious, right? The truth is that even modern softswitches and SBCs do not possess
the capability to simply install a new module or enable a feature to ensure proper behavior.  While the various
large operators will handle this internally, smaller providers faced with the same mandate as larger ones will have
difficulty handling this themselves.  In the meantime, it has been accepted that an upstream carrier (generally a large
wholesale carrier) can sign calls on behalf of the reselling carrier as the smaller carriers work towards self-signing.

Our goal with this project is to allow interconnected telcos of any size to sign their outgoing calls. This allows a
carrier full control over attestation level when representing their caller to the outside world. By deferring the signing
decision to an upstream provider, that provider may give a less desirable attestation level if they also did not provide
the telephone number represented by the caller ID as they simply cannot know purely based on their relationship with the
originating carrier.
## Requirements
### Business Requirements
* Current FCC 499-A
* An Operating Company Number (OCN), IPES version. More info [here](https://www.neca.org/business-solutions/company-codes)
* Completed Robocall Mitigation Filing [here](https://fccprod.servicenowservices.com/rmd?id=rmd_welcome)
* Register with the STI-PA (STIR/SHAKEN overseer) [here](https://authenticate.iconectiv.com/service-provider-authenticate)
* Active account at [Martini Security](https://martinisecurity.com) for ACME services
### Technical Requirements
* STI-PA API username, password, and services URL
* Register the allowed IP space on your network with the STI-PA. Two separate sets of STI-PA firewalls control access to staging and production environments.
  * WEB UI firewall IPv4/v6 primarily for bill pay
  * API firewall IPv4/v6 for reaching API endpoints (this software requires API access)
* An ECDSA SHA256 certificate and key for signing calls (must descend from STI-PA CA list). Cert and key can be acquired and configured statically or dynamically with ACME.
  * Please ensure the private key is not PKCS8 wrapped
## Core Frameworks and Dependencies
* [Gin/Gonic](https://github.com/gin-gonic/gin) for handling web requests.
* [Go-Jose](https://github.com/square/go-jose/tree/v2.6.0) for handling JWT/JOSE operations.
## Features
* Trust Management
  * Automatic update for STI-PA CA list and CRL
* STI-AS (Authentication Server)
  * ACME-based lifecycle for signing cert acquisition and renewal 
  * Call Signing via web request as per [ATIS-100082](https://access.atis.org/apps/group_public/download.php/40781/ATIS-1000082.pdf)
  * Simplified call signing via web request to expedite call signing by delivering a friendly SIP header
* STI-VS (Verification Server)
  * Call verification via web request as per [ATIS-100082](https://access.atis.org/apps/group_public/download.php/40781/ATIS-1000082.pdf)
  * Simplified verification via web request to assist simpler/naive SIP engines
  * Opportunistic cert/cert chain caching to expedite signed call verification
## Example Operation (In-Spec)
For full explanation, refer to the ATIS document referenced above. In all cases, identity is a Base64 encoded signed
but not encrypted JWT in compact form.
### Signing Request
Request JSON (pretty printed):
~~~
{
   "signingRequest" : {
      "iat" : 1632412033,
      "origid" : "de305d54-75b4-431b-adb2-eb6b9e546014",
      "orig" : {
         "tn" : "12155551212"
      },
      "attest" : "A",
      "dest" : {
         "tn" : [
            "12355551212"
         ]
      }
   }
}
~~~
Curl Test:
~~~
curl -X POST -H "Content-Type: application/json" -d '<JSON HERE>' http://127.0.0.1:8080/stir/v1/signing
~~~
Response JSON (pretty printed):
~~~
{
   "signingResponse" : {
      "identity" : "<header>.<payload>.<signature>;info=<https://my.certchain.url/dir/mycoolcert.pem>;alg=ES256;ppt=shaken"
   }
}
~~~
### Verification Request
Request JSON (pretty printed):
~~~
{
   "verificationRequest" : {
      "to" : {
         "tn" : [
            "12155551212"
         ]
      },
      "from" : {
         "tn" : "12355551212"
      },
      "identity" : "<header>.<payload>.<signature>;info=<https://other.certchain.url/dir/othercoolcert.pem>;alg=ES256;ppt=shaken",
      "time" : 1632413071
   }
}
~~~
Curl Test:
~~~
curl -X POST -H "Content-Type: application/json" -d '<JSON HERE>' http://127.0.0.1:8080/stir/v1/verification
~~~
Response JSON (pretty printed):
~~~
{
   "verificationResponse" : {
      "verstat" : "TN-Validation-Passed"
   }
}
~~~
## Example Operation (Quick Version)
Corner cutting version designed for quicker operation but not _technically_ in alignment with ATIS specs.
### Signing Request
This API endpoint expects a GET (or an empty body POST) where the path specifies the params. In all cases, the iat is
calculated to be the current time. The response body is designed to be directly appended as a SIP header.

`/ezstir/v1/signing/:orig/:dest/:attest/*origid` - Specify all other fields (optional origid)  
`/ezstir/v1/signing/:orig/:dest/` - Specify just the orig and dest and assume A attestation

Curl Tests:
~~~
curl http://127.0.0.1:8080/ezstir/v1/signing/12355551212/12155551212/B/96c2e54f-7998-43f0-947c-b54498b72b22
curl http://127.0.0.1:8080/ezstir/v1/signing/12355551212/12155551212/C
curl http://127.0.0.1:8080/ezstir/v1/signing/12355551212/12155551212
~~~
Response Text:
~~~
Identity: <header>.<payload>.<signature>;info=<https://my.certchain.url/dir/mycoolcert.pem>;alg=ES256;ppt=shaken
~~~
### Verification Request
This API endpoint expects a GET (or an empty body POST) where the path specifies the source and destination telephone
numbers and the SIP identity header. The quick verification API allows the call processing engine / SBC to naively send
the SIP FROM and P-Asserted-ID as the source and the TO and RURI as the destination.

If either of the two possible sources matches the source from the identity header, and either of the two possible
destinations matches the destination from the identity header, then the two/from information is seen as valid.

Quick verification still ensures that the iat is fresh and that the attestation is one of the allowed values.

`/ezstir/v1/verification/:from/:pai/:to/:ruri/*identity` - Params from, pai, to, and ruri must all be present. It is
recommended that pai and ruri just inherit the from and to respectively if no values would otherwise exist.

Curl Test:
~~~
curl http://127.0.0.1:8080/stir/v1/verification/12355551212/12355551212/12155551212/12155551212/<SIP Identity Header>
~~~
Response Text:

`NO-SIGNATURE` - No signature was presented.

`BAD-SIGNATURE` - Something about the JWT and/or signing cert/chain was seen as invalid.

`MISMATCH-<Attestation>` - Signature was valid, but the supplied source and/or destination could not be matched to the
data within the identity header. Attestation from identity header is still presented.

`VALID-<Attestion>` - Identity header has been verified and matches the call setup info. Attestation level is presented
in the response.
## Installation/Setup
### RPM-based
#### RHEL6
+ Install RPM
+ Customize /etc/vermouth (see config example)
+ Start it with "service vermouth start"
+ Test
#### RHEL7+
+ Install RPM
+ Customize /etc/vermouth (see config example)
+ Enable the vermouth.service with "systemctl enable vermouth.service"
+ Start the service with "systemctl start vermouth"
+ Test
#### Ubuntu Server LTS 16+
+ Install DEB package
+ Customize /etc/vermouth (see config example)
+ Enable the vermouth.service with "systemctl enable vermouth.service"
+ Start the service with "systemctl start vermouth"
+ Test
### Manual Execution
+ Build binary *Requires Go 1.19.
+ Specify global configuration file. It can be specified in two ways: 1.
  Passed in as an argument (`config="path/to/my/config.yml"`) or 2. As an environmental variable called
  `VERMOUTH_CONFIG`.
+ Execute binary
### Disclosure of Telemetry
Telemetry is collected to assess how many organizations are utilizing Vermouth. Its continued use will
spur us to keep up with evolving ATIS standards and continue to provide this software to whomever 
might need it. In addition, these metrics will let us see where our software may be failing to meet its stated
goals. Finally, this data can help us identify problems in the STIR/SHAKEN ecosystem. For example, an unusually high 
failure rate on call verifications with a cause of "untrusted" might cause us to examine whether these are really signatures from a bad chain or a misconfiguration or revocation issue.

However, if you wish to opt out of metric reporting add/modify the following line under the
`server:` section of the config file: `telemetry_disabled: true`.
### Basic Config Example
Note that the configuration file is in yml format.
~~~
server:
  # Listening ip/port
  listen_points: <IP:Port>
  # Basic remote admin done via username and password.
  # **Only execute admin requests locally**
  admin_api_username: <you.should.change.this>
  admin_api_password: <you.should.also.change.this>
sti_pa:
  api_user_id: <sti-pa user>
  api_password: <sti-pa pass>
sti_as:
  # Your carrier OCN
  carrier_ocn: <OCN>
  # Martini Prod vs Staging
  acme_prod_enabled: true
  # ACME private key location and filename
  acme_acct_key_file: certs/acme/acme.key
  # EAB key ID & Secret are available from your vendor
  acme_eab_key_id: ""
  acme_eab_key_secret: ""
  # ACME cert home
  acme_dir: <certs/acme>
database:
  # Enables local postgres database connection to record signing and verficiation info.
  enabled: false
  host:
  port:
  db_name:
  username:
  password:
~~~
PSQL Database Creation (if above option for enabling pgsql connection is desired):
~~~
CREATE TABLE public.signing_record (
    id bigint NOT NULL,
    sign_stamp timestamp with time zone DEFAULT now() NOT NULL,
    src_tn text NOT NULL,
    dst_tn text NOT NULL,
    attestation text NOT NULL,
    orig_id text NOT NULL
);

CREATE SEQUENCE public.signing_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.signing_id_seq OWNED BY public.signing_record.id;

CREATE TABLE public.verification_record (
    id bigint NOT NULL,
    verification_stamp timestamp with time zone DEFAULT now() NOT NULL,
    sip_from text,
    sip_pai text,
    sip_to text,
    sip_ruri text,
    identity text,
    x5u_url text,
    cert_chain_raw text,
    status_no_signature integer DEFAULT 0 NOT NULL,
    status_bad_format integer DEFAULT 0 NOT NULL,
    status_not_trusted integer DEFAULT 0 NOT NULL,
    status_invalid_signature integer DEFAULT 0 NOT NULL,
    status_tn_mismatch integer DEFAULT 0 NOT NULL,
    status_stale integer DEFAULT 0 NOT NULL,
    status_valid integer DEFAULT 0 NOT NULL,
    attestation text,
    orig_ocn text
);

CREATE SEQUENCE public.verification_record_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.verification_record_id_seq OWNED BY public.verification_record.id;

ALTER TABLE ONLY public.signing_record ALTER COLUMN id SET DEFAULT nextval('public.signing_id_seq'::regclass);

ALTER TABLE ONLY public.verification_record ALTER COLUMN id SET DEFAULT nextval('public.verification_record_id_seq'::regclass);

ALTER TABLE ONLY public.signing_record
    ADD CONSTRAINT signing_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.verification_record
    ADD CONSTRAINT verification_record_pkey PRIMARY KEY (id);

CREATE INDEX ix_signing_dst_tn ON public.signing_record USING btree (dst_tn);
CREATE INDEX ix_signing_orig ON public.signing_record USING btree (orig_id);
CREATE INDEX ix_signing_src_tn ON public.signing_record USING btree (src_tn);
CREATE INDEX ix_verification_from ON public.verification_record USING btree (sip_from);
CREATE INDEX ix_verification_ocn ON public.verification_record USING btree (orig_ocn);
CREATE INDEX ix_verification_pai ON public.verification_record USING btree (sip_pai);
CREATE INDEX ix_verification_ruri ON public.verification_record USING btree (sip_ruri);
CREATE INDEX ix_verification_to ON public.verification_record USING btree (sip_to);
CREATE INDEX ix_verification_x5u ON public.verification_record USING btree (x5u_url);
~~~