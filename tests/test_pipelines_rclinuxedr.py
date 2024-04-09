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
                    SourceHostname: host_name_here
                condition: sel
        """)
    ) == ['event_type_cd:network_connection AND ((domain:domain_here OR host_name:domain_here) AND protocol_cd:protocol_here AND (local_ip:ipaddress_value OR remote_ip:ipaddress_value) AND (local_port:destination_port_titleized OR remote_port:destination_port_titleized) AND (local_ip:destination_ip_titleized OR remote_ip:destination_ip_titleized) AND (local_ip:source_ip_titleized OR remote_ip:source_ip_titleized) AND (local_port:source_port_titleized OR remote_port:source_port_titleized) AND (local_port:source_port_titleized_short OR remote_port:source_port_titleized_short) AND (local_port:destination_port_titleized_short OR remote_port:destination_port_titleized_short) AND dst_ip_type:destination_ip_type_here AND src_ip_type:source_ip_type_here AND (domain:host_name_here OR host_name:host_name_here))']

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
                    SourceHostname: host_name_here
                condition: sel
        """)
    ) == ['event_type_cd:network_connection AND (host_name:domain_here AND protocol_cd:protocol_here AND (local_ip:ipaddress_value OR remote_ip:ipaddress_value) AND local_port:destination_port_titleized AND local_ip:destination_ip_titleized AND remote_ip:source_ip_titleized AND remote_port:source_port_titleized AND remote_port:source_port_titleized_short AND local_port:destination_port_titleized_short AND local_ip_type:destination_ip_type_here AND remote_ip_type:source_ip_type_here AND direction_cd:inbound AND domain:host_name_here)']

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
                    SourceHostname: host_name_here
                condition: sel
        """)
    ) == ['event_type_cd:network_connection AND (domain:domain_here AND protocol_cd:protocol_here AND (local_ip:ipaddress_value OR remote_ip:ipaddress_value) AND remote_port:destination_port_titleized AND remote_ip:destination_ip_titleized AND local_ip:source_ip_titleized AND local_port:source_port_titleized AND local_port:source_port_titleized_short AND remote_port:destination_port_titleized_short AND remote_ip_type:destination_ip_type_here AND local_ip_type:source_ip_type_here AND direction_cd:outbound AND host_name:host_name_here)']

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