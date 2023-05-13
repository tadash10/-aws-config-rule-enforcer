import boto3

# Define AWS Config rules
rules = [
    {
        'rule_name': 'EC2-ENCRYPTED-VOLUMES',
        'resource_type': 'AWS::EC2::Volume',
        'parameters': {
            'encrypted': {
                'StaticValue': {
                    'Values': ['true']
                }
            }
        }
    },
    {
        'rule_name': 'S3-BUCKET-PUBLIC-READ-PROHIBITED',
        'resource_type': 'AWS::S3::Bucket',
        'parameters': {
            'publicReadAccess': {
                'StaticValue': {
                    'Values': ['false']
                }
            }
        }
    }
]

# Create AWS Config client
config_client = boto3.client('config')

# Loop through rules and create or update them
for rule in rules:
    try:
        config_client.put_config_rule(
            ConfigRule={
                'ConfigRuleName': rule['rule_name'],
                'Scope': {
                    'ComplianceResourceTypes': [
                        rule['resource_type']
                    ]
                },
                'Source': {
                    'Owner': 'AWS',
                    'SourceIdentifier': 'AWS_CONFIG_RULES'
                },
                'InputParameters': json.dumps(rule['parameters'])
            }
        )
    except config_client.exceptions.InvalidParameterValueException:
        print(f"Failed to create rule {rule['rule_name']}. Invalid parameters.")

# Evaluate rules
for rule in rules:
    evaluations = config_client.get_compliance_details_by_config_rule(
        ConfigRuleName=rule['rule_name']
    )['EvaluationResults']

    if len(evaluations) > 0:
        non_compliant_resources = [eval['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId'] for eval in evaluations if eval['ComplianceType'] != 'COMPLIANT']
        if len(non_compliant_resources) > 0:
            print(f"Rule {rule['rule_name']} has non-compliant resources: {non_compliant_resources}")

