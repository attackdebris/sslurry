# SSLurry

## SSLurry - A quick and dirty .nessus file parser to extract hosts/services affected by SSL related issues

I've been testing on a large number of heavily populated internal subnets recently. Accurately reporting SSL protocol/cipher and certificate related issues can be time consuming in such scenarios, time that can be utilised more effectively identifying issues not reported by automated scanners and/or assessing more significant issues.

Due to the sheer size of some target environments our testing remit may only extend to identifing services affected by common SSL related failings rather than detailing the more granular issue e.g. report expired certificates are in use but don't detail the valid before/valid after dates.

To save some time and some of sanity in dealing with this problem the python3 script sslslurry.py was born, example output below:

Obviously making use of sslurry should be caveated by the fact that the usual potential false positives reported by Nessus will still be present e.g. certificates reported as being untrusted even if signed by a trusted internal certificate authority.

Installation:
```
git clone https://github.com/attackdebris/sslurry.git
```

Usage:
```
python3 sslurry.py [.nessus_file]
```
