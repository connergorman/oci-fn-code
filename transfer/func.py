import io
import os
import json
import sys
import base64
import logging
import warnings

from fdk import response
import oci.object_storage
import boto3
from botocore.config import Config
import botocore

def handler(ctx, data: io.BytesIO=None):
    # this is a new comment
    try:
        body = json.loads(data.getvalue())
        bucket_name = body["data"]["additionalDetails"]["bucketName"]
        object_name = body["data"]["resourceName"]
    except Exception:
        error = 'Input a JSON object in the format: \'{"bucketName": "<bucket name>"}, "objectName": "<object name>"}\' '
        raise Exception(body)
    signer = oci.auth.signers.get_resource_principals_signer()
    get_resp = get_object(bucket_name, object_name, signer)

    put_resp = put_object("receive-from-oci", object_name, get_resp["content"], signer)
    if put_resp == False:
        logging.getLogger().error("Upload failed")
        return response.Response(
            ctx,
            response_data="Upload failed",
            headers={"Content-Type": "application/json"}
        )
    return response.Response(
        ctx,
        response_data="Upload succssful",
        headers={"Content-Type": "application/json"}
    )

def get_object(bucket_name, object_name, signer):
    
    client = oci.object_storage.ObjectStorageClient(config={}, signer=signer)
    namespace = client.get_namespace().data
    try:
        print("Searching for bucket and object", flush=True)
        object = client.get_object(namespace, bucket_name, object_name)
        print("found object", flush=True)
        logging.getLogger().info("Found object.")
        if object.status == 200:
            print("Success: The object " + object_name + " was retrieved with the content: " + object.data.text, flush=True)
            message = object.data.text
        else:
            message = "Failed: The object " + object_name + " could not be retrieved."
    except Exception as e:
        message = "Failed: " + str(e.message)
    return { "content": message }


def put_object(bucket_name, object_name, content, signer):
    # Get AWS secret
    logging.getLogger().info("Starting principal signer")
    client = oci.secrets.SecretsClient(config={}, signer=signer)
    logging.getLogger().info("Got token")
    logging.getLogger().info("Trying to get aws creds from vault")
    try:
        response = client.get_secret_bundle(secret_id="ocid1.vaultsecret.oc1.iad.amaaaaaapc6swyaavfxklakk4cgkbii4grau27umnsmxoos5y4t5psqljbba")
        logging.getLogger().info("Got secret from vault")
    except Exception as e:
        raise Exception("Failed to get secret from Vault")
    b64_secret = response.data.secret_bundle_content.content
    secret = base64.b64decode(b64_secret).decode('utf-8')

    logging.getLogger().info("Get aws client")
    try:
        os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
        s3_client = boto3.client(
            's3',
            aws_access_key_id='AKIAUMKYHCUXXPUXVX5S',
            aws_secret_access_key=secret
        )
    except Exception as e:
        logging.getLogger().error("AWS client failed")
        raise Exception("AWS client failed") from e

        
    try:
        response = s3_client.put_object(Body=bytes(content, encoding='utf8'), Bucket=bucket_name, Key=object_name)
        logging.getLogger().info("Put successful")
    except botocore.exceptions.ClientError as e:
        logging.getLogger().error("AWS s3 failed")
        return False
    return True