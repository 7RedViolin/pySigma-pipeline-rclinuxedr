from typing import Optional, Union
from sigma.pipelines.common import logsource_windows, windows_logsource_mapping
from sigma.pipelines.base import Pipeline
from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation, DetectionItemFailureTransformation, RuleFailureTransformation, SetStateTransformation, ChangeLogsourceTransformation, DetectionItemTransformation, FieldPrefixMappingTransformation, MapStringTransformation
from sigma.processing.postprocessing import EmbedQueryTransformation
from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition, ExcludeFieldCondition, RuleProcessingItemAppliedCondition, RuleContainsDetectionItemCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline, QueryPostprocessingItem
from sigma.rule import SigmaDetectionItem, SigmaDetection
from sigma.exceptions import SigmaTransformationError
from sigma.types import SigmaString
from sigma.conditions import ConditionOR

class InvalidFieldTransformation(DetectionItemFailureTransformation):
    """
    Overrides the apply_detection_item() method from DetectionItemFailureTransformation to also include the field name
    in the error message
    """

    def apply_detection_item(self, detection_item: SigmaDetectionItem) -> None:
        field_name = detection_item.field
        self.message = f"Invalid SigmaDetectionItem field name encountered: {field_name}. " + self.message
        raise SigmaTransformationError(self.message)

## Custom DetectionItemTransformation to support *IsIPv6 fields, if applicable
class IsIPv6ValuesTransformation(DetectionItemTransformation):
    """Custom DetectionItemTransformation to add conditions if one or more *IsIPv6 fields are present
    Use with field_name_condition for *IsIPv6 field"""

    def apply_detection_item(self, detection_item: SigmaDetectionItem) -> Optional[
        Union[SigmaDetection, SigmaDetectionItem]]:
        to_return = []
        if not isinstance(detection_item.value, list):
            detection_item.value = [detection_item.value]
        for d in detection_item.value:
            if d.to_plain() == 'true':
                to_return.append(SigmaDetectionItem(field="local_ip_type", modifiers=[], value=[SigmaString("ipv6")]))
                to_return.append(SigmaDetectionItem(field="remote_ip_type", modifiers=[], value=[SigmaString("ipv6")]))
            else:
                to_return.append(SigmaDetectionItem(field="local_ip_type", modifiers=[], value=[SigmaString("ipv4")]))
                to_return.append(SigmaDetectionItem(field="remote_ip_type", modifiers=[], value=[SigmaString("ipv4")]))
        return SigmaDetection(detection_items=to_return, item_linking=ConditionOR)

## Custom DetectionItemTransformation to support Initiated field
class InitiatedValueTransformation(DetectionItemTransformation):
    """Custom DetectionItemTransformation for Initiated field
    Use with field_name_condition for Initiated field"""

    def apply_detection_item(self, detection_item: SigmaDetectionItem) -> Optional[
        Union[SigmaDetection, SigmaDetectionItem]]:
        to_return = []
        if not isinstance(detection_item.value, list):
            detection_item.value = [detection_item.value]
        for d in detection_item.value:
            if d.to_plain() == 'true':
                to_return.append(SigmaDetectionItem(field="direction_cd", modifiers=[], value=[SigmaString("outbound")]))
            else:
                to_return.append(SigmaDetectionItem(field="direction_cd", modifiers=[], value=[SigmaString("inbound")]))
        return SigmaDetection(detection_items=to_return, item_linking=ConditionOR)


@Pipeline
def RCLinuxEDR_pipeline() -> ProcessingPipeline:        # Processing pipelines should be defined as functions that return a ProcessingPipeline object.

    unsupported_os = [
        ProcessingItem(
            identifier="rclinuxedr_linux_os",
            transformation=RuleFailureTransformation("Product type not yet supported by the RC LinuxEDR Sigma pipeline"),
            rule_condition_negation=True,
            rule_conditions=[
                LogsourceCondition(product="linux")
            ]
        )
    ]

    event_type_translation_dict = {
        "process_creation": {
            "event_type_cd": "process_start"
        },
        "network_connection": {
            "event_type_cd": "network_connection"
        },
        "firewall": {
            "event_type_cd": "network_connection"
        }
    }

    translation_dict = {
        "ProcessId":"process_pid",
        "Image":"process_path",
        "ImagePath":"process_path",
        "CommandLine":"process_command_line",
        "CurrentDirectory":"working_directory",
        "User":["user_name", "login_user_name"],
        "md5":"process_md5",
        "sha256":"process_sha256",
        "ParentProcessId":"parent_process_pid",
        "ParentImage":"parent_process_path_name",
        "ParentImagePath":"parent_process_path",
        #?: "user_uid",
        #?: "login_user_uid",
        #?: "container_id",
        #?: "container_pod_id",
    }

    network_translation_dict = {
        "DestinationHostname":"domain",
        "Protocol": "protocol_cd",
        "IpAddress": ["local_ip", "remote_ip"],
        "DestinationPort":"dst_port",
        "DestinationIp":"dst_ip",
        "SourceIp":"src_ip",
        "SourcePort":"src_port",
        "SrcPort": "src_port",
        "DstPort": "dst_port",
        "DestinationIsIPv6": "dst_ip_type",
        "SourceIsIPv6": "src_ip_type"
        #?: "remote_location_cd",
    }

    network_unknown_direction_translation_dict = {
        "src_ip": ["local_ip","remote_ip"],
        "dst_ip": ["local_ip","remote_ip"],
        "src_port": ["local_port", "remote_port"],
        "dst_port":["local_port", "remote_port"],
    }

    other_supported_fields = [
        "Initiated",
    ]

    event_type_filter = [
        ProcessingItem(
            identifier=f"rclinuxedr_{event_type}_mapping",
            transformation=AddConditionTransformation(details),
            rule_conditions=[
                LogsourceCondition(category=event_type)
            ]
        )
        for event_type, details in event_type_translation_dict.items()
    ]

    field_mappings = [
        ProcessingItem(
            identifier="rclinuxedr_fieldmapping",
            transformation=FieldMappingTransformation(translation_dict),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="process_creation")
            ]
        ),
    ]

    network_field_mappings = [
        # Direction
        ProcessingItem(
            identifier="rclinuxedr_network_direction_fieldmapping",
            transformation=InitiatedValueTransformation(),
            field_name_conditions=[IncludeFieldCondition(['Initiated'])]
        ),

        # Initial mapping
        ProcessingItem(
            identifier="rclinuxedr_network_generic_fieldmapping",
            transformation=FieldMappingTransformation(network_translation_dict),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="network_connection"),
                LogsourceCondition(category="firewall")
            ]
        ),

        # Update prefixes if outbound
        ProcessingItem(
            identifier="rclinuxedr_network_outbound_fieldmapping",
            transformation=FieldPrefixMappingTransformation({"src": "local", "dst": "remote"}),
            field_name_conditions=[IncludeFieldCondition(network_translation_dict.values())],
            rule_conditions=[
                RuleContainsDetectionItemCondition(field="direction_cd", value="outbound")
            ]
        ),

        # Update prefixes if inbound
        ProcessingItem(
            identifier="rclinuxedr_network_inbound_fieldmapping",
            transformation=FieldPrefixMappingTransformation({"dst": "local", "src": "remote"}),
            field_name_conditions=[IncludeFieldCondition(network_translation_dict.values())],
            rule_conditions=[
                RuleContainsDetectionItemCondition(field="direction_cd", value="inbound")
            ]
        ),

        # Update prefixes if direction is unknown
        ProcessingItem(
            identifier="rclinuxedr_network_unknowndir_fieldmapping",
            transformation=FieldMappingTransformation(network_unknown_direction_translation_dict),
            field_name_conditions=[IncludeFieldCondition(network_translation_dict.values())],
            rule_condition_negation=True,
            rule_condition_linking=all,
            rule_conditions=[
                RuleContainsDetectionItemCondition(field="direction_cd", value="inbound"),
                RuleContainsDetectionItemCondition(field="direction_cd", value="outbound")
            ]
        ),

        # DestinationIsIPv6 and SourceIsIpv6
        ProcessingItem(
            identifier="rclinuxedr_network_iptype_fieldmapping",
            transformation=MapStringTransformation({"false": "ipv4", "true": "ipv6"}),
            field_name_conditions=[
                IncludeFieldCondition(["remote_ip_type", "local_ip_type"])
            ]
        ),
    ]

    change_logsource_info = [
        # Add service to be CarbonBlackResponse for pretty much everything
        ProcessingItem(
            identifier="rclinuxedr_logsource",
            transformation=ChangeLogsourceTransformation(
                service="rclinuxedr"
            ),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="process_creation"),
                LogsourceCondition(category="network_connection"),
                LogsourceCondition(category="firewall")
            ]
        ),
    ]

    unsupported_rule_types = [
        # Show error if unsupported option
        ProcessingItem(
            identifier="rclinuxedr_fail_rule_not_supported",
            rule_condition_linking=any,
            transformation=RuleFailureTransformation("Rule type not yet supported by the RC LinuxEDR Sigma pipeline"),
            rule_condition_negation=True,
            rule_conditions=[
                RuleProcessingItemAppliedCondition("rclinuxedr_logsource")
            ]
        )
    ]

    unsupported_field_names = [
        ProcessingItem(
            identifier="rclinuxedr_fail_field_name_not_supported",
            transformation=InvalidFieldTransformation("The supported fields are: {" + 
                "}, {".join(sorted(list(translation_dict.keys()) + list(network_translation_dict.keys()) + other_supported_fields + list(network_unknown_direction_translation_dict.keys()))) + '}'),
            field_name_conditions=[
                ExcludeFieldCondition(fields=list(translation_dict.keys()) + list(network_translation_dict.keys()) + other_supported_fields + list(network_unknown_direction_translation_dict.keys()))
            ],
            field_name_condition_linking=any
        )
    ]

    return ProcessingPipeline(
        name="rclinuxedr pipeline",
        allowed_backends=frozenset(),                                               # Set of identifiers of backends (from the backends mapping) that are allowed to use this processing pipeline. This can be used by frontends like Sigma CLI to warn the user about inappropriate usage.
        priority=50,            # The priority defines the order pipelines are applied. See documentation for common values.
        items=[
            *unsupported_os,
            *unsupported_field_names,
            *event_type_filter,
            *field_mappings,
            *network_field_mappings,
            *change_logsource_info,
            *unsupported_rule_types
        ]
    )