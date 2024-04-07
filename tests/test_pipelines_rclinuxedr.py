import pytest
from sigma.collection import SigmaCollection
from sigma.backends.test import TextQueryTestBackend
from sigma.pipelines.rclinuxedr import RCLinuxEDR_pipeline# TODO: import pipeline functions

@pytest.fixture
def test_backend():
  return TextQueryTestBackend(RCLinuxEDR_pipeline())

def test_rclinuxedr_unsupported_os(test_backend : TextQueryTestBackend):
    with pytest.raises(ValueError): 
      test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    Image: valueA
                condition: sel
        """)
    )

def test_rclinuxedr_process_creation_mapping(test_backend : TextQueryTestBackend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: linux
            detection:
                sel:
                    ProcessId: process_pid_here
                    Image: process_path_here
                    ImagePath: process_path_here
                    CommandLine: process_command_line_here
                    CurrentDirectory: working_directory_here
                    User: user_name_and_login_user_name_here
                    md5: process_md5_here
                    sha256: sha256_here
                    ParentProcessId: parent_process_pid_here
                    ParentImage: parent_process_path_here
                    ParentImagePath: parent_process_path_here
                condition: sel
        """)
    ) == ['event_type_cd="process_start" and process_pid="process_pid_here" and process_path="process_path_here" and process_path="process_path_here" and process_command_line="process_command_line_here" and working_directory="working_directory_here" and (user_name="user_name_and_login_user_name_here" or login_user_name="user_name_and_login_user_name_here") and process_md5="process_md5_here" and process_sha256="sha256_here" and parent_process_pid="parent_process_pid_here" and parent_process_path_name="parent_process_path_here" and parent_process_path="parent_process_path_here"']

def test_rclinuxedr_network_no_direction_mapping(test_backend : TextQueryTestBackend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: network_connection
                product: linux
            detection:
                sel:
                    DestinationHostname: domain_here
                    Protocol: protocol_here
                    IpAddress: ipaddress_value
                    DestinationPort: destination_port_titleized
                    DestinationIp: destination_ip_titleized
                    SourceIp: source_ip_titleized
                    SourcePort: source_port_titleized
                    SrcPort: source_port_titleized_short
                    DstPort: destination_port_titleized_short
                    DestinationIsIPv6: destination_ip_type_here
                    SourceIsIPv6: source_ip_type_here
                condition: sel
        """)
    ) == ['event_type_cd="network_connection" and domain="domain_here" and protocol_cd="protocol_here" and (local_ip="ipaddress_value" or remote_ip="ipaddress_value") and (local_port="destination_port_titleized" or remote_port="destination_port_titleized") and (local_ip="destination_ip_titleized" or remote_ip="destination_ip_titleized") and (local_ip="source_ip_titleized" or remote_ip="source_ip_titleized") and (local_port="source_port_titleized" or remote_port="source_port_titleized") and (local_port="source_port_titleized_short" or remote_port="source_port_titleized_short") and (local_port="destination_port_titleized_short" or remote_port="destination_port_titleized_short") and dst_ip_type="destination_ip_type_here" and src_ip_type="source_ip_type_here"']

def test_rclinuxedr_network_inbound_mapping(test_backend : TextQueryTestBackend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: network_connection
                product: linux
            detection:
                sel:
                    DestinationHostname: domain_here
                    Protocol: protocol_here
                    IpAddress: ipaddress_value
                    DestinationPort: destination_port_titleized
                    DestinationIp: destination_ip_titleized
                    SourceIp: source_ip_titleized
                    SourcePort: source_port_titleized
                    SrcPort: source_port_titleized_short
                    DstPort: destination_port_titleized_short
                    DestinationIsIPv6: destination_ip_type_here
                    SourceIsIPv6: source_ip_type_here
                    Initiated: 'false'
                condition: sel
        """)
    ) == ['event_type_cd="network_connection" and domain="domain_here" and protocol_cd="protocol_here" and (local_ip="ipaddress_value" or remote_ip="ipaddress_value") and local_port="destination_port_titleized" and local_ip="destination_ip_titleized" and remote_ip="source_ip_titleized" and remote_port="source_port_titleized" and remote_port="source_port_titleized_short" and local_port="destination_port_titleized_short" and local_ip_type="destination_ip_type_here" and remote_ip_type="source_ip_type_here" and direction_cd="inbound"']

def test_rclinuxedr_network_outbound_mapping(test_backend : TextQueryTestBackend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: network_connection
                product: linux
            detection:
                sel:
                    DestinationHostname: domain_here
                    Protocol: protocol_here
                    IpAddress: ipaddress_value
                    DestinationPort: destination_port_titleized
                    DestinationIp: destination_ip_titleized
                    SourceIp: source_ip_titleized
                    SourcePort: source_port_titleized
                    SrcPort: source_port_titleized_short
                    DstPort: destination_port_titleized_short
                    DestinationIsIPv6: destination_ip_type_here
                    SourceIsIPv6: source_ip_type_here
                    Initiated: 'true'
                condition: sel
        """)
    ) == ['event_type_cd="network_connection" and domain="domain_here" and protocol_cd="protocol_here" and (local_ip="ipaddress_value" or remote_ip="ipaddress_value") and remote_port="destination_port_titleized" and remote_ip="destination_ip_titleized" and local_ip="source_ip_titleized" and local_port="source_port_titleized" and local_port="source_port_titleized_short" and remote_port="destination_port_titleized_short" and remote_ip_type="destination_ip_type_here" and local_ip_type="source_ip_type_here" and direction_cd="outbound"']

def test_rclinuxedr_unsupported_rule_type(test_backend : TextQueryTestBackend):
  with pytest.raises(ValueError):
    test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: linux
            detection:
                sel:
                    Image: valueA
                    CommandLine: invoke-mimikatz
                    ParentImage: valueB
                    ParentCommandLine: Get-Path
                condition: sel
        """)
    )

def test_rclinuxedr_unsupported_field_name(test_backend : TextQueryTestBackend):
  with pytest.raises(ValueError):
    test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: linux
            detection:
                sel:
                    FOO: bar
                condition: sel
        """)
    )