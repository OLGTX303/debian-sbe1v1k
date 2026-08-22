"""sbegw — control plane for the Askey SBE1V1K (IPQ9574) DIY gateway router.

Layering (see doc/gateway_sepicafication.txt and doc/wifi_subsystem.txt):

    api          REST/SSE surface, auth + RBAC
    configd      candidate/running config, transactional commit, audit
    netd         ports, bridges, VLANs, networks, WANs, firewall, NAT, DHCP/DNS
    wifid        radios, SSIDs, BSSes, MLO/MLD, wireless clients
    clientd      unified wired + wireless client database
    telemetryd   sampling, rates, bounded retention
    eventd       event history and live fan-out
    adapters     the only code that touches iproute2/nft/iw/hostapd/QSDK

This is a do-it-yourself project, not a commercial product.
"""

__version__ = "0.1.0"
