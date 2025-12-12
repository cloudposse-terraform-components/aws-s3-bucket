package test

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/cloudposse/test-helpers/pkg/atmos"
	helper "github.com/cloudposse/test-helpers/pkg/atmos/component-helper"
	"github.com/gruntwork-io/terratest/modules/aws"
	"github.com/stretchr/testify/assert"
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

func (s *ComponentSuite) TestEventNotifications() {
	const component = "s3-bucket/event-notifications"
	const stack = "default-test"
	const awsRegion = "us-east-2"

	// Get AWS config for SDK v2
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(awsRegion))
	assert.NoError(s.T(), err)

	// Create SNS client
	snsClient := sns.NewFromConfig(cfg)

	// Create an SNS topic for testing
	randomID := randomString(8)
	topicName := fmt.Sprintf("s3-event-test-%s", randomID)
	createTopicOutput, err := snsClient.CreateTopic(ctx, &sns.CreateTopicInput{
		Name: &topicName,
	})
	assert.NoError(s.T(), err)
	topicArn := *createTopicOutput.TopicArn

	// Ensure cleanup of SNS topic
	defer func() {
		_, _ = snsClient.DeleteTopic(ctx, &sns.DeleteTopicInput{
			TopicArn: &topicArn,
		})
	}()

	// Set SNS topic policy to allow S3 to publish
	snsPolicy := fmt.Sprintf(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"Service": "s3.amazonaws.com"},
			"Action": "sns:Publish",
			"Resource": "%s"
		}]
	}`, topicArn)
	_, err = snsClient.SetTopicAttributes(ctx, &sns.SetTopicAttributesInput{
		TopicArn:       &topicArn,
		AttributeName:  strPtr("Policy"),
		AttributeValue: &snsPolicy,
	})
	assert.NoError(s.T(), err)

	// Override vars to include our SNS topic
	vars := map[string]interface{}{
		"event_notification_details": map[string]interface{}{
			"enabled":     true,
			"eventbridge": false,
			"lambda_list": []interface{}{},
			"queue_list":  []interface{}{},
			"topic_list": []interface{}{
				map[string]interface{}{
					"topic_arn":     topicArn,
					"events":        []string{"s3:ObjectCreated:*"},
					"filter_prefix": "uploads/",
					"filter_suffix": ".json",
				},
			},
		},
	}

	defer s.DestroyAtmosComponent(s.T(), component, stack, &vars)
	options, _ := s.DeployAtmosComponent(s.T(), component, stack, &vars)
	assert.NotNil(s.T(), options)

	bucketID := atmos.Output(s.T(), options, "bucket_id")
	assert.NotEmpty(s.T(), bucketID)

	// Create S3 client
	s3Client := s3.NewFromConfig(cfg)

	// Get bucket notification configuration
	notificationOutput, err := s3Client.GetBucketNotificationConfiguration(ctx, &s3.GetBucketNotificationConfigurationInput{
		Bucket: &bucketID,
	})
	assert.NoError(s.T(), err)

	// Verify EventBridge is NOT enabled
	assert.Nil(s.T(), notificationOutput.EventBridgeConfiguration, "EventBridgeConfiguration should be nil when eventbridge is false")

	// Verify SNS topic notification is configured
	assert.Len(s.T(), notificationOutput.TopicConfigurations, 1, "Should have exactly one topic configuration")
	if len(notificationOutput.TopicConfigurations) > 0 {
		topicConfig := notificationOutput.TopicConfigurations[0]
		assert.Equal(s.T(), topicArn, *topicConfig.TopicArn, "Topic ARN should match")
		assert.Contains(s.T(), topicConfig.Events, s3types.Event("s3:ObjectCreated:*"), "Should have ObjectCreated event")

		// Verify filter rules
		if topicConfig.Filter != nil && topicConfig.Filter.Key != nil {
			filterRules := topicConfig.Filter.Key.FilterRules
			var hasPrefix, hasSuffix bool
			for _, rule := range filterRules {
				if rule.Name == s3types.FilterRuleNamePrefix {
					assert.Equal(s.T(), "uploads/", *rule.Value)
					hasPrefix = true
				}
				if rule.Name == s3types.FilterRuleNameSuffix {
					assert.Equal(s.T(), ".json", *rule.Value)
					hasSuffix = true
				}
			}
			assert.True(s.T(), hasPrefix, "Should have prefix filter rule")
			assert.True(s.T(), hasSuffix, "Should have suffix filter rule")
		}
	}

	// Verify no Lambda or Queue configurations
	assert.Empty(s.T(), notificationOutput.LambdaFunctionConfigurations, "LambdaFunctionConfigurations should be empty")
	assert.Empty(s.T(), notificationOutput.QueueConfigurations, "QueueConfigurations should be empty")

	s.DriftTest(component, stack, &vars)
}

// strPtr returns a pointer to the given string
func strPtr(s string) *string {
	return &s
}

// randomString generates a random lowercase alphanumeric string of the given length
func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[r.Intn(len(charset))]
	}
	return string(b)
}

func TestRunSuite(t *testing.T) {
	suite := new(ComponentSuite)
	helper.Run(t, suite)
}
