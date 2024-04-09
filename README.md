![Tests](https://github.com/7RedViolin/pySigma-pipeline-rclinuxedr/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/7RedViolin/71e0645bb5e484316692e2122f3c2c55/raw/7RedViolin-pySigma-pipeline-rclinuxedr.json)
![Status](https://img.shields.io/badge/Status-release-green)

# pySigma RC LinuxEDR Pipeline

This is the RC LinuxEDR pipeline for pySigma. It contains the processing pipeline `sigma.pipelines.rclinuxedr` for field renames and error handling. It is mainly written for the Telemetry Search functionality (Elasticsearch Lucene backend with `default` output) but can also be used to generate DSL queries (Elasticsearch Lucene backend with `dsl_lucene` output).

This pipeline is currently maintained by:

* [Cori Smith](https://github.com/7RedViolin/)


## Installation
This can be installed via pip from PyPI or using pySigma's plugin functionality

### PyPI
```bash
pip install pysigma-pipeline-rclinuxedr
```

### pySigma
```python
from sigma.plugins import SigmaPluginDirectory
plugins = SigmaPluginDirectory.default_plugin_directory()
plugins.get_plugin_by_id("rclinuxedr").install()
```

## Usage

### sigma-cli
```bash
sigma convert -t rclinuxedr proc_creation_lnx_at_command.yml
```

### pySigma
```python
from sigma.backends.elasticsearch import LuceneBackend
from sigma.pipelines.rclinuxedr import RCLinuxEDR_pipeline
from sigma.rule import SigmaRule

rule = SigmaRule.from_yaml("""
title: Mimikatz CommandLine
status: test
logsource:
    category: process_creation
    product: linux
detection:
    sel:
        CommandLine|contains: mimikatz
    condition: sel""")


backend = LuceneBackend(RCLinuxEDR_pipeline())
print(backend.convert_rule(rule)[0])
```

## Side Notes & Limitations
- Pipeline uses RC Linux EDR field names
- Pipeline only supports `linux` product type
- Pipeline supports the following category types for field mappings
  - `process_creation`
  - `network_connection`
  - `firewall`
- Pipeline supports the following fields:
  - `CommandLine`
  - `CurrentDirectory`
  - `DestinationHostname`
  - `DestinationIp`
  - `DestinationgIsIPv6`
  - `DestinationPort`
  - `DstIP`
  - `DstPort`
  - `Initiated`
  - `IpAddress`
  - `ParentImage`
  - `ParentImagePath`
  - `ParentProcessId`
  - `ProcessId`
  - `Protocol`
  - `SrcIp`
  - `SrcPort`
  - `SourceHostname`
  - `SourceIp`
  - `SourceIsIPv6`
  - `SourcePort`
  - `User`
  - `dst_host`
  - `dst_ip`
  - `dst_port`
  - `md5`
  - `sha256`
  - `src_host`
  - `src_ip`
  - `src_port`
- Any unsupported fields or categories will throw errors
