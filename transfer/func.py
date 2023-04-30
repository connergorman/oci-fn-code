import io
import os
import json
import sys
import base64

from fdk import response
import oci.object_storage
import boto3
from botocore.config import Config

def handler(ctx, data: io.BytesIO=None):
    try:
        body = json.loads(data.getvalue())
        bucket_name = body["bucketName"]
        object_name = body["objectName"]
    except Exception:
        error = 'Input a JSON object in the format: \'{"bucketName": "<bucket name>"}, "objectName": "<object name>"}\' '
        raise Exception(error)
    get_resp = get_object(bucket_name, object_name)
    put_resp = put_object("receive-from-oci", object_name, get_resp.content)
    return response.Response(
        ctx,
        response_data=json.dumps(put_resp),
        headers={"Content-Type": "application/json"}
    )

def get_object(bucket_name, object_name):
    signer = oci.auth.signers.get_resource_principals_signer()
    client = oci.object_storage.ObjectStorageClient(config={}, signer=signer)
    namespace = client.get_namespace().data
    try:
        print("Searching for bucket and object", flush=True)
        object = client.get_object(namespace, bucket_name, object_name)
        print("found object", flush=True)
        if object.status == 200:
            print("Success: The object " + object_name + " was retrieved with the content: " + object.data.text, flush=True)
            message = object.data.text
        else:
            message = "Failed: The object " + object_name + " could not be retrieved."
    except Exception as e:
        message = "Failed: " + str(e.message)
    return { "content": message }


def put_object(bucket_name, object_name, content):
    # Get AWS secret
    signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
    client = oci.secrets.SecretsClient(config={}, signer=signer)
    response = client.get_secret_bundle(secret_id="ocid1.vaultsecret.oc1.iad.amaaaaaapc6swyaavfxklakk4cgkbii4grau27umnsmxoos5y4t5psqljbba")
    b64_secret = response.data.secret_bundle_content.content
    secret = base64.b64decode(b64_secret).decode('utf-8')

    
    s3_client = boto3.client(
        's3',
        aws_access_key_id='AKIAUMKYHCUXXPUXVX5S',
        aws_secret_access_key=secret,
        aws_default_region='us-ashburn-1'
    )

        
    try:
        response = s3_client.put_object(Body=bytes(content), Bucket=bucket_name, Key=object_name)
    except boto3.ClientError as e:
        return False
    return True