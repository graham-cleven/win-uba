config = {
    # offsets to correct for ingestion latency
    "host-lat": 10,
    "net-lat": 20,
    # Splunk options
    "splunk-pwd": "b3ZlclRoZU1vb24uNjY2",
    "splunk-host": "localhost",
    "splunk-user": "root",
    "splunk-port": "8089",
    # index / sourcetype options
    "net-index": "bro",
    "host-index": "windows",
    "dhcp-type": "dhcp",
    # field settings
    "field-event": "EventCode",
}
