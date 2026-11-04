//! Reviewable plans and dedicated sandbox artifacts; no AWS changes are executed.
use crate::{
    config::{GuardError, validate_config, validate_snapshot},
    domain::*,
};

pub fn plan(
    c: &TargetConfig,
    snapshot: Option<&InventorySnapshot>,
) -> Result<ChangePlan, GuardError> {
    validate_config(c)?;
    if let Some(s) = snapshot {
        validate_snapshot(c, s)?;
    }
    let mut changes = Vec::new();
    let mut push = |code: &str, required: bool, ids: &[&str]| {
        changes.push(PlanItem {
            code: code.into(),
            required,
            verification_ids: ids.iter().map(|s| (*s).into()).collect(),
        })
    };
    push("REVIEW_ACCOUNT_REGION_COST_AND_SOURCE", true, &["V01"]);
    if let Some(s) = snapshot {
        let db = s.db.as_ref();
        let proxy = s.proxy.as_ref();
        push(
            "REVIEW_DB_IAM_ENABLEMENT",
            db.is_none_or(|d| !d.iam_auth_enabled),
            &["V03"],
        );
        push(
            "REVIEW_PROXY_END_TO_END_IAM",
            proxy.is_none_or(|p| p.auth_mode != c.auth.mode),
            &["V03"],
        );
        push(
            "REVIEW_PROXY_TLS_REQUIRED",
            proxy.is_none_or(|p| !p.require_tls),
            &["V08"],
        );
        push(
            "REVIEW_DB_TLS_AND_PARAMETER_APPLICATION",
            db.is_none_or(|d| d.force_ssl != Some(true) || !d.parameters_in_sync),
            &["V08"],
        );
        push("REVIEW_PUBLIC_AND_ALL_SECURITY_GROUP_PATHS", true, &["V09"]);
    } else {
        push(
            "INVENTORY_REQUIRED_BEFORE_EXISTING_DB_CHANGE",
            true,
            &["V01"],
        );
    }
    push(
        "BOOTSTRAP_DEDICATED_DB_USER_AND_SCOPE",
        true,
        &["V03", "V06"],
    );
    push(
        "VERIFY_PROXY_POSITIVE_AND_AUTH_TLS_NEGATIVES",
        true,
        &["V06", "V07", "V08"],
    );
    push("VERIFY_APPLICATION_DIRECT_PATH_DENIAL", true, &["V09"]);
    push(
        "PRESERVE_ADMIN_RECOVERY_PATH_AND_BASELINE",
        true,
        &["V12", "V13"],
    );
    push(
        "ROLLBACK_APPLICATION_ENDPOINT_BEFORE_NETWORK_REVERSION",
        true,
        &["V12", "V17"],
    );
    push(
        "REVIEW_RETENTION_AND_EXPLICIT_SANDBOX_CLEANUP",
        true,
        &["V21"],
    );
    let mut unknowns = Vec::new();
    if snapshot.is_none_or(|s| {
        s.retrievals
            .iter()
            .any(|r| r.status != RetrievalStatus::Complete)
            || s.db.is_none()
            || s.proxy.is_none()
    }) {
        unknowns.push(ReasonCode::SnapshotIncomplete);
    }
    unknowns.push(ReasonCode::MissingEvidence);
    Ok(ChangePlan {
        schema_version: 1,
        target_id: c.target.id.clone(),
        operation_only: true,
        snapshot_available: snapshot.is_some(),
        changes,
        unknowns,
        bootstrap_required: true,
    })
}

fn sandbox_scope(c: &TargetConfig) -> Option<&TestScope> {
    if validate_config(c).is_err()
        || !matches!(
            c.assessment_profile,
            Profile::LocalContractV1 | Profile::AwsSandboxCoreV1
        )
    {
        return None;
    }
    c.test_scope
        .as_ref()
        .filter(|s| s.database.starts_with("vdg_") && s.db_user.starts_with("vdg_"))
}
/// Unapplied, dedicated NEW sandbox only. This template never imports the configured DB ARN.
pub fn validate_sandbox(c: &TargetConfig) -> Result<(), GuardError> {
    sandbox_scope(c)
        .map(|_| ())
        .ok_or(GuardError::ConfigInvalid)
}
pub fn sandbox_template(c: &TargetConfig) -> String {
    let Some(scope) = sandbox_scope(c) else {
        return "# CONFIG_INVALID: dedicated NEW sandbox scope required\n".into();
    };
    TEMPLATE
        .replace("@DBUSER@", &c.auth.db_user)
        .replace("@DATABASE@", &scope.database)
        .replace("@VERSION@", &c.target.engine_version)
}
/// Operator-run bootstrap for the NEW sandbox only, never an existing-DB migration script.
pub fn bootstrap_sql(c: &TargetConfig) -> String {
    let Some(scope) = sandbox_scope(c) else {
        return "-- CONFIG_INVALID: dedicated NEW sandbox scope required\n".into();
    };
    format!(
        r#"-- UNAPPLIED: ONLY the NEW database created by the accompanying sandbox CloudFormation.
-- Compare the deployed DatabaseArn output and administrator endpoint before execution.
-- Do not run on an existing/customer DB; naming and current_user guards are not proof of provenance.
-- Run psql with ON_ERROR_STOP=1 against database "{database}" through the ADMIN path.
-- CREATE is granted only on this dedicated synthetic-data database: each probe creates a
-- run-owned schema with configured prefix "{schema}". CONNECT alone would make CREATE SCHEMA fail.
-- PostgreSQL 16 basis: https://www.postgresql.org/docs/16/sql-createschema.html
-- Not idempotent: an existing role causes an error and the transaction must roll back.
BEGIN;
DO $vdg_guard$
BEGIN
  IF current_database() <> '{database}' OR current_user <> 'bootstrap_admin' THEN
    RAISE EXCEPTION 'VDG_SANDBOX_TARGET_MISMATCH';
  END IF;
END
$vdg_guard$;
CREATE ROLE "{user}" LOGIN;
GRANT rds_iam TO "{user}";
GRANT CONNECT, CREATE ON DATABASE "{database}" TO "{user}";
COMMIT;
-- No cleanup is performed here. Preserve evidence and review owned test resources before removal.
-- Recovery: retain administrator path; change app endpoint only after baseline verification.
"#,
        database = scope.database,
        user = c.auth.db_user,
        schema = scope.schema_prefix
    )
}
const TEMPLATE: &str = r#"AWSTemplateFormatVersion: '2010-09-09'
Description: 'UNAPPLIED Veil DB Guard dedicated NEW sandbox. Review costs, SQL bootstrap, runner staging and cleanup before deployment.'
# Never import an existing DB. This creates charged resources if an operator deploys it.
# Runners are private SSM hosts, not internet endpoints. Stage the CLI/psql through an approved
# offline mechanism or a reviewed image: this template does not install/download application code.
# Bootstrap uses the separate AdminRunner path. ApplicationRunner and DeniedRunner cannot connect
# directly to DB, and their roles cannot read the master secret. No workloads are automatically run.
Parameters:
  SandboxId:
    Type: String
    Default: vdgsandbox
    AllowedPattern: '[a-z][a-z0-9]{2,25}'
  DatabaseInstanceClass:
    Type: String
    Default: db.t4g.medium
    AllowedValues: [db.t4g.medium, db.t4g.large]
  RunnerInstanceType:
    Type: String
    Default: t4g.small
    AllowedValues: [t4g.small, t4g.medium]
  RunnerImage:
    Type: AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>
    Default: /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.72.0.0/16
      EnableDnsSupport: true
      EnableDnsHostnames: true
      Tags: [{Key: Purpose, Value: veil-db-guard-sandbox}]
  SubnetA:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.72.1.0/24
      AvailabilityZone: !Select [0, !GetAZs '']
      MapPublicIpOnLaunch: false
  SubnetB:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.72.2.0/24
      AvailabilityZone: !Select [1, !GetAZs '']
      MapPublicIpOnLaunch: false
  AppSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Sandbox application and denied-principal runners
      VpcId: !Ref Vpc
  AdminSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Separate bootstrap and recovery runner
      VpcId: !Ref Vpc
  ProxySecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Only declared application runners to Proxy
      VpcId: !Ref Vpc
      SecurityGroupIngress:
        - {IpProtocol: tcp, FromPort: 5432, ToPort: 5432, SourceSecurityGroupId: !Ref AppSecurityGroup}
  DbSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Proxy plus explicit administrator exception only
      VpcId: !Ref Vpc
      SecurityGroupIngress:
        - {IpProtocol: tcp, FromPort: 5432, ToPort: 5432, SourceSecurityGroupId: !Ref ProxySecurityGroup}
        - {IpProtocol: tcp, FromPort: 5432, ToPort: 5432, SourceSecurityGroupId: !Ref AdminSecurityGroup}
  EndpointSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Private SSM HTTPS from declared runners only
      VpcId: !Ref Vpc
      SecurityGroupIngress:
        - {IpProtocol: tcp, FromPort: 443, ToPort: 443, SourceSecurityGroupId: !Ref AppSecurityGroup}
        - {IpProtocol: tcp, FromPort: 443, ToPort: 443, SourceSecurityGroupId: !Ref AdminSecurityGroup}
  SsmEndpoint:
    Type: AWS::EC2::VPCEndpoint
    Properties:
      VpcEndpointType: Interface
      VpcId: !Ref Vpc
      ServiceName: !Sub com.amazonaws.${AWS::Region}.ssm
      PrivateDnsEnabled: true
      SubnetIds: [!Ref SubnetA, !Ref SubnetB]
      SecurityGroupIds: [!Ref EndpointSecurityGroup]
  SsmMessagesEndpoint:
    Type: AWS::EC2::VPCEndpoint
    Properties:
      VpcEndpointType: Interface
      VpcId: !Ref Vpc
      ServiceName: !Sub com.amazonaws.${AWS::Region}.ssmmessages
      PrivateDnsEnabled: true
      SubnetIds: [!Ref SubnetA, !Ref SubnetB]
      SecurityGroupIds: [!Ref EndpointSecurityGroup]
  SecretsEndpoint:
    Type: AWS::EC2::VPCEndpoint
    Properties:
      VpcEndpointType: Interface
      VpcId: !Ref Vpc
      ServiceName: !Sub com.amazonaws.${AWS::Region}.secretsmanager
      PrivateDnsEnabled: true
      SubnetIds: [!Ref SubnetA, !Ref SubnetB]
      SecurityGroupIds: [!Ref EndpointSecurityGroup]
  DbSubnetGroup:
    Type: AWS::RDS::DBSubnetGroup
    Properties:
      DBSubnetGroupDescription: Dedicated sandbox private database subnets
      SubnetIds: [!Ref SubnetA, !Ref SubnetB]
  DbParameters:
    Type: AWS::RDS::DBParameterGroup
    Properties:
      Description: Sandbox TLS is mandatory
      Family: postgres16
      Parameters: {rds.force_ssl: '1'}
  Database:
    Type: AWS::RDS::DBInstance
    DeletionPolicy: Snapshot
    UpdateReplacePolicy: Snapshot
    Properties:
      DBInstanceIdentifier: !Sub ${SandboxId}-db
      Engine: postgres
      EngineVersion: '@VERSION@'
      DBInstanceClass: !Ref DatabaseInstanceClass
      DBName: '@DATABASE@'
      AllocatedStorage: '20'
      StorageType: gp3
      StorageEncrypted: true
      PubliclyAccessible: false
      MultiAZ: false
      EnableIAMDatabaseAuthentication: true
      DBSubnetGroupName: !Ref DbSubnetGroup
      DBParameterGroupName: !Ref DbParameters
      VPCSecurityGroups: [!Ref DbSecurityGroup]
      MasterUsername: bootstrap_admin
      ManageMasterUserPassword: true
      BackupRetentionPeriod: 1
      AutoMinorVersionUpgrade: false
      CopyTagsToSnapshot: true
      Tags: [{Key: Purpose, Value: veil-db-guard-sandbox}]
  ProxyRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal: {Service: rds.amazonaws.com}
            Action: sts:AssumeRole
            Condition: {StringEquals: {'aws:SourceAccount': !Ref AWS::AccountId}}
      Policies:
        - PolicyName: SandboxDatabaseUserOnly
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: rds-db:connect
                Resource: !Sub arn:${AWS::Partition}:rds-db:${AWS::Region}:${AWS::AccountId}:dbuser:${Database.DbiResourceId}/@DBUSER@
  Proxy:
    Type: AWS::RDS::DBProxy
    Properties:
      DBProxyName: !Sub ${SandboxId}-proxy
      EngineFamily: POSTGRESQL
      DefaultAuthScheme: IAM_AUTH
      RequireTLS: true
      DebugLogging: false
      IdleClientTimeout: 300
      RoleArn: !GetAtt ProxyRole.Arn
      VpcSubnetIds: [!Ref SubnetA, !Ref SubnetB]
      VpcSecurityGroupIds: [!Ref ProxySecurityGroup]
  ProxyTargetGroup:
    Type: AWS::RDS::DBProxyTargetGroup
    Properties:
      DBProxyName: !Ref Proxy
      TargetGroupName: default
      DBInstanceIdentifiers: [!Ref Database]
      ConnectionPoolConfigurationInfo:
        MaxConnectionsPercent: 50
        MaxIdleConnectionsPercent: 25
        ConnectionBorrowTimeout: 10
  AppRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement: [{Effect: Allow, Principal: {Service: ec2.amazonaws.com}, Action: sts:AssumeRole}]
      ManagedPolicyArns: [!Sub 'arn:${AWS::Partition}:iam::aws:policy/AmazonSSMManagedInstanceCore']
      Policies:
        - PolicyName: SandboxProxyUserOnly
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: rds-db:connect
                Resource: !Sub
                  - arn:${AWS::Partition}:rds-db:${AWS::Region}:${AWS::AccountId}:dbuser:${ProxyResourceId}/@DBUSER@
                  - ProxyResourceId: !Select [6, !Split [':', !GetAtt Proxy.DBProxyArn]]
  DeniedRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement: [{Effect: Allow, Principal: {Service: ec2.amazonaws.com}, Action: sts:AssumeRole}]
      ManagedPolicyArns: [!Sub 'arn:${AWS::Partition}:iam::aws:policy/AmazonSSMManagedInstanceCore']
      # Deliberately no rds-db:connect. Same SG/path as ApplicationRunner.
  AdminRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement: [{Effect: Allow, Principal: {Service: ec2.amazonaws.com}, Action: sts:AssumeRole}]
      ManagedPolicyArns: [!Sub 'arn:${AWS::Partition}:iam::aws:policy/AmazonSSMManagedInstanceCore']
      Policies:
        - PolicyName: SandboxBootstrapSecretOnly
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: secretsmanager:GetSecretValue
                Resource: !GetAtt Database.MasterUserSecret.SecretArn
  AppProfile:
    Type: AWS::IAM::InstanceProfile
    Properties: {Roles: [!Ref AppRole]}
  DeniedProfile:
    Type: AWS::IAM::InstanceProfile
    Properties: {Roles: [!Ref DeniedRole]}
  AdminProfile:
    Type: AWS::IAM::InstanceProfile
    Properties: {Roles: [!Ref AdminRole]}
  ApplicationRunner:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: !Ref RunnerImage
      InstanceType: !Ref RunnerInstanceType
      SubnetId: !Ref SubnetA
      SecurityGroupIds: [!Ref AppSecurityGroup]
      IamInstanceProfile: !Ref AppProfile
      MetadataOptions: {HttpTokens: required, HttpEndpoint: enabled}
      Tags: [{Key: Purpose, Value: veil-db-guard-sandbox}]
  DeniedRunner:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: !Ref RunnerImage
      InstanceType: !Ref RunnerInstanceType
      SubnetId: !Ref SubnetA
      SecurityGroupIds: [!Ref AppSecurityGroup]
      IamInstanceProfile: !Ref DeniedProfile
      MetadataOptions: {HttpTokens: required, HttpEndpoint: enabled}
      Tags: [{Key: Purpose, Value: veil-db-guard-sandbox}]
  AdminRunner:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: !Ref RunnerImage
      InstanceType: !Ref RunnerInstanceType
      SubnetId: !Ref SubnetB
      SecurityGroupIds: [!Ref AdminSecurityGroup]
      IamInstanceProfile: !Ref AdminProfile
      MetadataOptions: {HttpTokens: required, HttpEndpoint: enabled}
      Tags: [{Key: Purpose, Value: veil-db-guard-sandbox}]
Outputs:
  DatabaseArn: {Value: !GetAtt Database.DBInstanceArn}
  DatabaseEndpoint: {Value: !GetAtt Database.Endpoint.Address}
  ProxyArn: {Value: !GetAtt Proxy.DBProxyArn}
  ProxyName: {Value: !Ref Proxy}
  ProxyEndpoint: {Value: !GetAtt Proxy.Endpoint}
  ApplicationRunnerId: {Value: !Ref ApplicationRunner}
  DeniedRunnerId: {Value: !Ref DeniedRunner}
  AdminRunnerId: {Value: !Ref AdminRunner}
  BootstrapSecretArn: {Value: !GetAtt Database.MasterUserSecret.SecretArn}
  DeploymentStatus: {Value: 'UNVERIFIED: stage tools, run reviewed bootstrap SQL, inspect and probe before assessment'}
# Recovery: retain admin access and evidence; revert application connection settings only with
# an approved baseline path. Stack deletion is a separately approved operation. Snapshot policy
# retains a charged final DB snapshot. Inventory and delete residual resources only after review.
"#;
