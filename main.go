package main

import (
	"encoding/json"
	"fmt"
	"os"

	//"github.com/aws/aws-sdk-go/service/iam"
	awsPolicy "github.com/n4ch04/aws-policy"
)

const (
	policyDocVersion = "2012-10-17"
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

	err = buildPolicy(string(filedata))
	if err != nil {
		fmt.Println(err)
	}
}

func buildPolicy(policyString string) error {

	policy := awsPolicy.Policy{}

	err := policy.UnmarshalJSON([]byte(policyString))
	if err != nil {
		return err
	}

	policyJSON, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Print(string(policyJSON))

	return nil
}
