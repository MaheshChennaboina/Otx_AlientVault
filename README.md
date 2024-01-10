# Otx_AlientVault
This Python script utilizes the AlienVault OTX (Open Threat Exchange) API to retrieve HTTP scan information for a list of IP addresses stored in an Excel file.

sections:

**general**: General information about the IP, such as geo data, and a list of the other sections currently available for this IP address.
**reputation**: OTX data on malicious activity observed by AlienVault Labs (IP Reputation).
**geo**: A more verbose listing of geographic data (Country code, coordinates, etc.)
**malware**: Malware samples analyzed by AlienVault Labs which have been observed connecting to this IP address.
**url_list**: URLs analyzed by AlienVault Labs which point to or are somehow associated with this IP address.
**passive_dns**: passive dns information about hostnames/domains observed by AlienVault Labs pointing to this IP address.
**http_scans**: Meta data for http(s) connections to the IP.

Example: api/v1/indicators/IPv4/8.8.8.8/general
Example : https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/http_scans
