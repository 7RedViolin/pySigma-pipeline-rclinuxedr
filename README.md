![Tests](https://github.com/7RedViolin/pySigma-pipeline-rclinuxedr/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/7RedViolin/71e0645bb5e484316692e2122f3c2c55/raw/7RedViolin-pySigma-pipeline-rclinuxedr.json)
![Status](https://img.shields.io/badge/Status-release-green)

# pySigma RC LinuxEDR Pipeline

This is the RC LinuxEDR pipeline for pySigma. It contains the processing pipeline `sigma.pipelines.rclinuxedr` for field renames and error handling. It is mainly written for the Telemetry Search functionality (Elasticsearch Lucene backend with `default` output) but can also be used to generate DSL queries (Elasticsearch Lucene backend with `dsl_lucene` output).

This pipeline is currently maintained by:

* [Cori Smith](https://github.com/7RedViolin/)