# Certificate Transparency Log Monitor for Splunk

This add-on for Splunk can be used to monitor certificate transparency logs.
For example to watch certificates issued for your domains or malicious look-a-likes.

It outputs the certificate logs as events in Splunk. This allows you to create an alert in Splunk or Splunk Enterprise Security that fires when a certificate gets issued for your-domain.suspicious-fishing-domain.tld.

## Supported Splunk versions and platforms

| Splunk version | Linux | Windows
|----------------|-------|---------
| 6.3            | Yes   | Yes
| 6.4            | Yes   | Yes
| 6.5            | Yes   | Yes
| 6.6            | Yes   | Yes
| 7.0            | Yes   | Yes
| 7.1            | Yes   | Yes

Additional requirements:

* Splunk heavy forwarder instance: Splunk Universal Forwarder is not supported due to Python dependencies
* KVstore: used to keep track of the most recently seen ct log entry

## Install the TA-ct-log add-on for Splunk

### Single instance Splunk deployments

1. In Splunk, click on "Manage Apps"
2. Click "Browse more apps", search for "TA-ct-log" and install the add-on

### Distributed Splunk deployments

| Instance type | Supported | Required | Description
|---------------|-----------|----------|------------
| Heavy Forwarder     | Yes | Yes      | Install this add-on on a heavy forwarder to get Certificate Transparency Logs into Splunk
| Search head   | Yes       | Yes      | Install this add-on on your search head(s) where CIM compliance of CT Logs is required
| Indexer       | Yes       | No       | There is no need to install this add-on on an indexer. This add-on should be installed on a heavy forwarder that does the index time parsing. 
| Universal Forwarder | No  | No       | This add-on is not supported on a Universal Forwarder because it requires Python

The following table lists support for distributed deployment roles in a Splunk deployment:

| Deployment role | Supported | Description
|-----------------|-----------|-------------
| Search head deployer | Yes  | Install this add-on on your search head deployer to enable CIM compliance of CT Logs in a Search Head Cluster
| Cluster Master       | No  | There is no need to install this add-on on a Cluster Master. This add-on should be installed on a heavy forwarder that performs parsing at index time. 
| Deployment Server    | Depends  | This add-on can be (1) deployed unconfigured to a client or (2) deployed preconfigured. 

## Configure TA-ct-log add-on for Splunk

![Input overview](appserver/static/screenshot.png)

1. Go to the Input tab of the Certificate Transparency add-on for Splunk
2. Click "Create new Input"
3. Configure:
    * Name: e.g. argon2018
    * Interval: how often to poll the certificate log for new entries
    * Index: what Splunk index to send the certificate log events to
    * Certificate Log URL: the base url of the log e.g. "ct.googleapis.com/logs/argon2018/", without https:// and without the API endpoint) for more urls see [https://www.gstatic.com/ct/log_list/all_logs_list.json](https://www.gstatic.com/ct/log_list/all_logs_list.json)

![Add a new input](appserver/static/screenshot2.png)

## Events in Splunk

The add-on extracts these certificate fields:

- Subject (DN)
- Issuer (DN)
- Public key bit size
- Public key type
- Certificate serial
- Certificate validity
- Certificate signature algorithm
- Certificate version
- Log metadata: LogEntryType (0=x509, 1=precert) and Timestamp

![Input overview](appserver/static/events.png)

## RFC6962

Chapter 5.3 of the RFC specifies a number of steps that a monitor should implement.
Currently only step 1, 3 and 7 are implemented.
These steps are enough to detect certificates requested by malicious actors other than the CA or CT Log operator.
The other steps involve signature checking that allow a monitor a breach to the append-only character of a log.
Feel free to submit a Pull Request, or wait for future releases to implement these features.
