package test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/cloudposse/test-helpers/pkg/atmos"
	helper "github.com/cloudposse/test-helpers/pkg/atmos/aws-component-helper"
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

func TestComponent(t *testing.T) {
	awsRegion := "us-east-2"

	fixture := helper.NewFixture(t, "../", awsRegion, "test/fixtures")

	defer fixture.TearDown()
	fixture.SetUp(&atmos.Options{})

	fixture.Suite("default", func(t *testing.T, suite *helper.Suite) {
		suite.Test(t, "basic", func(t *testing.T, atm *helper.Atmos) {
			defer atm.GetAndDestroy("s3-bucket/basic", "default-test", map[string]interface{}{})
			component := atm.GetAndDeploy("s3-bucket/basic", "default-test", map[string]interface{}{})
			assert.NotNil(t, component)

			bucketID := atm.Output(component, "bucket_id")
			assert.NotEmpty(t, bucketID)

			bucketARN := atm.Output(component, "bucket_arn")
			assert.True(t, strings.HasSuffix(bucketARN, bucketID))

			bucketRegion := atm.Output(component, "bucket_region")
			assert.Equal(t, "us-east-2", bucketRegion)

			bucketRegionalDomainName := atm.Output(component, "bucket_regional_domain_name")
			assert.Equal(t, fmt.Sprintf("%s.s3.%s.amazonaws.com", bucketID, awsRegion), bucketRegionalDomainName)

			bucketDomainName := atm.Output(component, "bucket_domain_name")
			assert.Equal(t, fmt.Sprintf("%s.s3.amazonaws.com", bucketID), bucketDomainName)

			versioning := aws.GetS3BucketVersioning(t, awsRegion, bucketID)
			assert.Equal(t, "Enabled", versioning)

			policyString := aws.GetS3BucketPolicy(t, awsRegion, bucketID)

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

			var policy BucketPolicy
			json.Unmarshal([]byte(policyString), &policy)

			statement := policy.Statement[0]

			assert.Equal(t, "DenyIncorrectEncryptionHeader", statement.Sid)
			assert.Equal(t, "s3:PutObject", statement.Action)
			assert.Equal(t, "Deny", statement.Effect)
			assert.Equal(t, fmt.Sprintf("arn:aws:s3:::%s/*", bucketID), statement.Resource)
			assert.Equal(t, "AES256", statement.Condition.StringNotEquals["s3:x-amz-server-side-encryption"])

			statement = policy.Statement[1]

			assert.Equal(t, "DenyUnEncryptedObjectUploads", statement.Sid)
			assert.Equal(t, "s3:PutObject", statement.Action)
			assert.Equal(t, "Deny", statement.Effect)
			assert.Equal(t, "arn:aws:s3:::eg-default-ue2-test-bd14af-998acf/*", statement.Resource)
			assert.Equal(t, "true", statement.Condition.Null["s3:x-amz-server-side-encryption"])

			statement = policy.Statement[2] // Access the new statement

			assert.Equal(t, "ForceSSLOnlyAccess", statement.Sid)
			assert.Equal(t, "s3:*", statement.Action)
			assert.Equal(t, "Deny", statement.Effect)
			assert.ElementsMatch(t, []string{
				fmt.Sprintf("arn:aws:s3:::%s/*", bucketID),
				fmt.Sprintf("arn:aws:s3:::%s", bucketID),
			}, statement.Resource) // Check for multiple resources
			assert.Equal(t, false, statement.Condition.Bool["aws:SecureTransport"]) // Check the Bool condition
		})
	})
}
