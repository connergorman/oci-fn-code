#!/usr/bin/bash

# Get aws creds out of Vault and put them into the environment for aws cli
export AWS_SECRET_ACCESS_KEY=$(oci secrets secret-bundle get --secret-id ocid1.vaultsecret.oc1.iad.amaaaaaapc6swyaaqyp22cyxipfwjq2qeurkaqkc2b6rgpnn6coxmkqjkoza --auth instance_principal | jq -r '.data."secret-bundle-content".content' | base64 --decode)
export AWS_ACCESS_KEY_ID=AKIAUMKYHCUXRF4QAED4
export AWS_DEFAULT_REGION=us-east-1

# Get docker auth token out of AWS and log into OCIR
aws secretsmanager get-secret-value --secret-id oracle/secrets | jq -r '.SecretString' | jq -r '."registry-token"' | docker login -u "idnvcl7rivjx/cnrgrmn3@gmail.com" --password-stdin iad.ocir.io