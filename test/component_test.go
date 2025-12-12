package test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/cloudposse/test-helpers/pkg/atmos"
	helper "github.com/cloudposse/test-helpers/pkg/atmos/component-helper"
	"github.com/gruntwork-io/terratest/modules/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type LifecyclePolicyRuleSelection struct {
	TagStatus     string   `json:"tagStatus"`
	TagPrefixList []string `json:"tagPrefixList"`
	CountType     string   `json:"countType"`
	CountNumber   int      `json:"countNumber"`
}

type LifecyclePolicyRule struct {
	RulePriority int                          `json:"rulePriority"`
	Description  string                       `json:"description"`
	Selection    LifecyclePolicyRuleSelection `json:"selection"`
	Action       map[string]string            `json:"action"`
}

type LifecyclePolicy struct {
	Rules []LifecyclePolicyRule `json:"rules"`
}

type BucketPolicy struct {
	Version   string `json:"Version"`
	Statement []struct {
		Sid       string      `json:"Sid,omitempty"`
		Principal string      `json:"Principal"`
		Effect    string      `json:"Effect"`
		Action    string      `json:"Action"`
		Resource  interface{} `json:"Resource"` // Changed to interface{} to accommodate array
		Condition struct {
			StringEquals    map[string]string `json:"StringEquals,omitempty"`
			StringNotEquals map[string]string `json:"StringNotEquals,omitempty"`
			Null            map[string]string `json:"Null,omitempty"`
			Bool            map[string]bool   `json:"Bool,omitempty"` // Added Bool for new condition
		} `json:"Condition"`
	} `json:"Statement"`
}

type EventNotificationConfig struct {
	EventBridgeConfiguration     bool
	LambdaFunctionConfigurations []string
	QueueConfigurations          []string
	TopicConfigurations          []string
}

type ComponentSuite struct {
	helper.TestSuite
}

func (s *ComponentSuite) TestBasic() {
	const component = "s3-bucket/basic"
	const stack = "default-test"
	const awsRegion = "us-east-2"

	defer s.DestroyAtmosComponent(s.T(), component, stack, nil)
	options, _ := s.DeployAtmosComponent(s.T(), component, stack, nil)
	assert.NotNil(s.T(), options)

	bucketID := atmos.Output(s.T(), options, "bucket_id")
	assert.NotEmpty(s.T(), bucketID)

	bucketARN := atmos.Output(s.T(), options, "bucket_arn")
	assert.True(s.T(), strings.HasSuffix(bucketARN, bucketID))

	bucketRegion := atmos.Output(s.T(), options, "bucket_region")
	assert.Equal(s.T(), "us-east-2", bucketRegion)

	bucketRegionalDomainName := atmos.Output(s.T(), options, "bucket_regional_domain_name")
	assert.Equal(s.T(), fmt.Sprintf("%s.s3.%s.amazonaws.com", bucketID, awsRegion), bucketRegionalDomainName)

	bucketDomainName := atmos.Output(s.T(), options, "bucket_domain_name")
	assert.Equal(s.T(), fmt.Sprintf("%s.s3.amazonaws.com", bucketID), bucketDomainName)

	versioning := aws.GetS3BucketVersioning(s.T(), awsRegion, bucketID)
	assert.Equal(s.T(), "Enabled", versioning)

	policyString := aws.GetS3BucketPolicy(s.T(), awsRegion, bucketID)

	var policy BucketPolicy
	json.Unmarshal([]byte(policyString), &policy)

	for _, statement := range policy.Statement {
		switch statement.Sid {
		case "DenyIncorrectEncryptionHeader":
			assert.Equal(s.T(), "s3:PutObject", statement.Action)
			assert.Equal(s.T(), "Deny", statement.Effect)
			assert.Equal(s.T(), fmt.Sprintf("arn:aws:s3:::%s/*", bucketID), statement.Resource)
			assert.Equal(s.T(), "AES256", statement.Condition.StringNotEquals["s3:x-amz-server-side-encryption"])
		case "DenyUnEncryptedObjectUploads":
			assert.Equal(s.T(), "s3:PutObject", statement.Action)
			assert.Equal(s.T(), "Deny", statement.Effect)
			assert.Equal(s.T(), fmt.Sprintf("arn:aws:s3:::%s/*", bucketID), statement.Resource)
			assert.Equal(s.T(), "true", statement.Condition.Null["s3:x-amz-server-side-encryption"])
		case "ForceSSLOnlyAccess":
			assert.Equal(s.T(), "s3:*", statement.Action)
			assert.Equal(s.T(), "Deny", statement.Effect)
			assert.ElementsMatch(s.T(), []string{
				fmt.Sprintf("arn:aws:s3:::%s/*", bucketID),
				fmt.Sprintf("arn:aws:s3:::%s", bucketID),
			}, statement.Resource)
			assert.Equal(s.T(), false, statement.Condition.Bool["aws:SecureTransport"])
		}
	}

	s.DriftTest(component, stack, nil)
}

func (s *ComponentSuite) TestEnabledFlag() {
	const component = "s3-bucket/disabled"
	const stack = "default-test"
	const awsRegion = "us-east-2"

	s.VerifyEnabledFlag(component, stack, nil)
}

func getS3BucketEventNotification(t *testing.T, region string, bucketName string) *EventNotificationConfig {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	require.NoError(t, err)

	client := s3.NewFromConfig(cfg)
	result, err := client.GetBucketNotificationConfiguration(ctx, &s3.GetBucketNotificationConfigurationInput{
		Bucket: &bucketName,
	})
	require.NoError(t, err)

	config := &EventNotificationConfig{
		EventBridgeConfiguration:     result.EventBridgeConfiguration != nil,
		LambdaFunctionConfigurations: []string{},
		QueueConfigurations:          []string{},
		TopicConfigurations:          []string{},
	}

	if result.LambdaFunctionConfigurations != nil {
		for _, lambdaConfig := range result.LambdaFunctionConfigurations {
			if lambdaConfig.LambdaFunctionArn != nil {
				config.LambdaFunctionConfigurations = append(config.LambdaFunctionConfigurations, *lambdaConfig.LambdaFunctionArn)
			}
		}
	}

	if result.QueueConfigurations != nil {
		for _, queueConfig := range result.QueueConfigurations {
			if queueConfig.QueueArn != nil {
				config.QueueConfigurations = append(config.QueueConfigurations, *queueConfig.QueueArn)
			}
		}
	}

	if result.TopicConfigurations != nil {
		for _, topicConfig := range result.TopicConfigurations {
			if topicConfig.TopicArn != nil {
				config.TopicConfigurations = append(config.TopicConfigurations, *topicConfig.TopicArn)
			}
		}
	}

	return config
}

func (s *ComponentSuite) TestEventNotifications() {
	const component = "s3-bucket/event-notifications"
	const stack = "default-test"
	const awsRegion = "us-east-2"

	defer s.DestroyAtmosComponent(s.T(), component, stack, nil)
	options, _ := s.DeployAtmosComponent(s.T(), component, stack, nil)
	assert.NotNil(s.T(), options)

	bucketID := atmos.Output(s.T(), options, "bucket_id")
	assert.NotEmpty(s.T(), bucketID)

	eventNotification := getS3BucketEventNotification(s.T(), awsRegion, bucketID)
	assert.NotNil(s.T(), eventNotification)
	assert.Equal(s.T(), false, eventNotification.EventBridgeConfiguration)
	assert.Equal(s.T(), []string{}, eventNotification.LambdaFunctionConfigurations)
	assert.Equal(s.T(), []string{}, eventNotification.QueueConfigurations)
	assert.Equal(s.T(), []string{}, eventNotification.TopicConfigurations)

	s.DriftTest(component, stack, nil)
}

func TestRunSuite(t *testing.T) {
	suite := new(ComponentSuite)
	helper.Run(t, suite)
}
