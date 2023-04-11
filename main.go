package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	awsPolicy "github.com/fahlmant/aws-policy"
)

const (
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html#reference_iam-quotas-entity-length
	// "The size of each managed policy cannot exceed 6,144 characters." This does not include whitespace
	managedPolicyCharLimit = 6144
	policyVersionString    = "2012-10-17"
)

func main() {

	// Simplistic check for a single argument
	if len(os.Args) <= 1 || len(os.Args) > 2 {
		fmt.Println("Please provide a single file name")
		return
	}

	filename := os.Args[1]

	filedata, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println(err)
	}

	if len(filedata) < managedPolicyCharLimit {
		fmt.Printf("No splitting needed, policy size of %d does not exceed max size of %d\n", len(filedata), managedPolicyCharLimit)
		return
	}

	err = splitPolicy(filename, filedata)
	if err != nil {
		fmt.Println(err)
	}
}

func splitPolicy(filename string, filecontents []byte) error {

	fileAsPolicy := awsPolicy.Policy{}

	err := fileAsPolicy.UnmarshalJSON(filecontents)
	if err != nil {
		return err
	}

	// Build dummy policy with no statements
	dummyPolicy := awsPolicy.Policy{
		Version: policyVersionString,
	}

	// Find the length of the dummy policy
	dummyJSON, err := getJSONfromPolicy(dummyPolicy)
	if err != nil {
		return err
	}

	var newPoliciesToBuild []awsPolicy.Policy
	statementIndex := 0
	// Loop until we're at the end of statements
	for {
		newPolicy := awsPolicy.Policy{}
		totalSize := len(string(dummyJSON))
		for {
			if statementIndex >= len(fileAsPolicy.Statements) {
				break
			}

			statement := fileAsPolicy.Statements[statementIndex]
			// Convert the struct to JSON to count characters
			statementAsJSON, err := getJSONfromStatemet(statement)
			if err != nil {
				return err
			}

			if totalSize+len(statementAsJSON)+1 < managedPolicyCharLimit {
				// Adding one for the comma
				totalSize += len(statementAsJSON) + 1
				newPolicy.Statements = append(newPolicy.Statements, statement)
				statementIndex += 1
			} else {
				break
			}
		}
		newPoliciesToBuild = append(newPoliciesToBuild, newPolicy)
		if statementIndex >= len(fileAsPolicy.Statements) {
			break
		}
	}

	for i, policy := range newPoliciesToBuild {
		// Build file name for new file
		newFilename := fmt.Sprintf("%s-%d.json", fileNameWithoutExtTrimSuffix(filename), i)
		// Add version to policy
		policy.Version = policyVersionString
		//Create file
		contents, err := getJSONfromPolicy(policy)
		if err != nil {
			return err
		}

		err = os.WriteFile(newFilename, contents, 0644)
		if err != nil {
			return err
		}
	}

	return nil
}

func getJSONfromStatemet(statement awsPolicy.Statement) ([]byte, error) {
	jsonStatemet, err := json.MarshalIndent(statement, "", "    ")
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return jsonStatemet, nil
}

func getJSONfromPolicy(policy awsPolicy.Policy) ([]byte, error) {
	jsonPolicy, err := json.MarshalIndent(policy, "", "    ")
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return jsonPolicy, nil
}

func fileNameWithoutExtTrimSuffix(fileName string) string {
	return strings.TrimSuffix(fileName, filepath.Ext(fileName))
}
