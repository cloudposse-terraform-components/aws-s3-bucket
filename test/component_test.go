package test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/cloudposse/test-helpers/pkg/atmos"
	helper "github.com/cloudposse/test-helpers/pkg/atmos/component-helper"
	"github.com/gruntwork-io/terratest/modules/aws"
	"github.com/stretchr/testify/assert"
)

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

	s.VerifyEnabledFlag(component, stack, nil)
}

func (s *ComponentSuite) TestEventNotifications() {
	const component = "s3-bucket/event-notifications"
	const stack = "default-test"

	defer s.DestroyAtmosComponent(s.T(), component, stack, nil)
	options, _ := s.DeployAtmosComponent(s.T(), component, stack, nil)
	assert.NotNil(s.T(), options)

	bucketID := atmos.Output(s.T(), options, "bucket_id")
	assert.NotEmpty(s.T(), bucketID)

	s.DriftTest(component, stack, nil)
}

func TestRunSuite(t *testing.T) {
	suite := new(ComponentSuite)
	helper.Run(t, suite)
}
