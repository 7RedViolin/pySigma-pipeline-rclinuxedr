from sigma.backends.elasticsearch import LuceneBackend
from sigma.pipelines.rclinuxedr import RCLinuxEDR_pipeline
from sigma.rule import SigmaRule
import re
import sys

rule = SigmaRule.from_yaml("""
            title: Test
            status: test
            logsource:
                category: network_connection
                product: linux
            detection:
                sel:
                    DestinationIsIPv6: "false"
                    Initiated: "true"
                    dst_ip: "10.0.0.0"
                condition: sel
""")


backend = LuceneBackend(RCLinuxEDR_pipeline())
print(backend.convert_rule(rule)[0])