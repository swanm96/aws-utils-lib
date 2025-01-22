import json
from pprint import pprint
import boto3
import string
from boto3.dynamodb.conditions import Key, Attr
import datetime

def globalSession(profile,table=None):
    global session
    session=boto3.Session(profile_name=profile)
    global gdb 
    global gbk
    global gbkResourse
    global lik
    global smk
    global sqsk
    global cgnk
    resource=session.resource('dynamodb')
    if table == None:
        gbk=session.client('s3')
        gbkResourse=session.resource('s3')
        lik=session.client('lambda')
        gdb=session.client('dynamodb')
        smk=session.client('secretsmanager')
        sqsk=session.client('sqs')
        cgnk=session.client('cognito-idp')
    else:
        gdb=resource.Table(table)
    return True

def isession(profile):
    isess=boto3.Session(profile_name=profile)
    return isess
 
 
def db(table, **kwargs):
    if "session" in kwargs:
       conn=kwargs["session"]
    else:
        conn=session
 
    resource=conn.resource('dynamodb')
    resource=resource.Table(table)
    return resource

def S3(**kwargs):
    if "session" in kwargs:
       conn=kwargs["session"]
    else:
        conn=session
    resource=conn.client('s3')
    return resource

def Lambda(**kwargs):
    if "session" in kwargs:
       conn=kwargs["session"]
    else:
        conn=session
    resource=conn.client('lambda')
    return resource

def SecretMgr(**kwargs):
    if "session" in kwargs:
       conn=kwargs["session"]
    else:
        conn=session
    resource=conn.client('secretsmanager')
    return resource

def SQS(**kwargs):
    if "session" in kwargs:
        conn=kwargs["session"]
    else:
        conn=session
    resource=conn.client('sqs')
    return resource

def Cognito(**kwargs):
    if "session" in kwargs:
        conn=kwargs["session"]
    else:
        conn=session
    resource=conn.client('cognito-idp')
    return resource

def queryWithIndex(value,key,index,**kwargs):
   
    if "tbname" in kwargs:        
        if "session" in kwargs:
            tb=db(table=kwargs["tbname"],session=kwargs["session"])
        else:
            tb=db(kwargs["tbname"])
    else:
        tb=gdb
    try:
        response= tb.query(
            IndexName=index,
            Select='ALL_ATTRIBUTES',
            KeyConditionExpression=Key(key).eq(value)
        )
        return response
    except:
        raise 

def queryWithKey(value,key,**kwargs):

    if "tbname" in kwargs:        
        if "session" in kwargs:
            tb=db(table=kwargs["tbname"],session=kwargs["session"])
        else:
            tb=db(kwargs["tbname"])
    else:
        tb=gdb
    try:
        response= tb.query(     
            KeyConditionExpression=Key(key).eq(value)
        )
        return response
    except:
        raise 

def putItem(**kwargs):
    if "tbname" in kwargs:        
        if "session" in kwargs:
            tb=db(table=kwargs["tbname"],session=kwargs["session"])
        else:
            tb=db(kwargs["tbname"])
    else:
        tb=gdb
    
    kwargs.pop('tbname',None)
    kwargs.pop('session',None)

    Items=json.dumps(kwargs)
    Items=json.loads(Items)    
    try:
        response= tb.put_item(     
            Item=Items
        )
        return response
    except:
        raise 

def deleteItem(key,value,**kwargs):
    if "tbname" in kwargs:        
        if "session" in kwargs:
            tb=db(table=kwargs["tbname"],session=kwargs["session"])
        else:
            tb=db(kwargs["tbname"])
    else:
        tb=gdb
    try:
        response = tb.delete_item(     
            Key={
                key:value
            }
        )
        return response
        #print("Registro eliminado")
    except:
        raise 

def deleteItemWithSortKey(key,value,sortkey,skvalue,**kwargs):
    if "tbname" in kwargs:        
        if "session" in kwargs:
            tb=db(table=kwargs["tbname"],session=kwargs["session"])
        else:
            tb=db(kwargs["tbname"])
    else:
        tb=gdb
    try:
        response = tb.delete_item(     
            Key={
                key:value,
                sortkey:skvalue
            }
        )
        return response
        #print("Registro eliminado")
    except:
        raise

def update(partkeyid,value,**kwargs):
    if "tbname" in kwargs:        
        if "session" in kwargs:
            tb=db(table=kwargs["tbname"],session=kwargs["session"])
        else:
            tb=db(kwargs["tbname"])
    else:
        tb=gdb
    datenow=datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]+'Z'
    abc =string.ascii_lowercase
    at=""
    ut=""
    ax=0
    index={}
    kwargs.pop('tbname',None)
    kwargs.pop('session',None)

    for key in kwargs.items():
        index[ax]=key[0]
        ax+=1
    ax=0    
    for key in index:
        ut=ut+index[ax] +"=:"+abc[ax]+", "
        ax+=1

    UExp="set "+ut+"UpdatedDate=:zz"
    ax=0    
    for key in index:
        at=at+'":'+abc[ax]+'":"'+kwargs[index[ax]]+'",'
        ax+=1
    EAVal='{'+at+'":zz":"'+datenow+'"}'
    EAVal = json.loads(EAVal)
    try:
        tb.update_item(        
                Key={
                    partkeyid:value
                },
                UpdateExpression=UExp,
                ExpressionAttributeValues=EAVal,
                ReturnValues="UPDATED_NEW"
            )
    except:
        raise
 
def updateWithSortKey(partkeyid,value,sortkeyid,skvalue,**kwargs):
    if "tbname" in kwargs:        
        if "session" in kwargs:
            tb=db(table=kwargs["tbname"],session=kwargs["session"])
        else:
            tb=db(kwargs["tbname"])
    else:
        tb=gdb
    datenow=datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]+'Z'
    abc =string.ascii_lowercase
    at=""
    ut=""
    ax=0
    index={}
    kwargs.pop('tbname',None)
    kwargs.pop('session',None)
    for key in kwargs.items():
        index[ax]=key[0]
        ax+=1
    ax=0    
    for key in index:
        ut=ut+index[ax] +"=:"+abc[ax]+", "
        ax+=1

    UExp="set "+ut+"UpdatedDate=:zz"
    ax=0    
    for key in index:
        at=at+'":'+abc[ax]+'":"'+kwargs[index[ax]]+'",'
        ax+=1
    EAVal='{'+at+'":zz":"'+datenow+'"}'
    EAVal = json.loads(EAVal)
    try:
        tb.update_item(        
                Key={
                    partkeyid:value,
                    sortkeyid:skvalue
                },
                UpdateExpression=UExp,
                ExpressionAttributeValues=EAVal,
                ReturnValues="UPDATED_NEW"
            )
    except:
        raise

#----------------------------------

def getItem(partkeyid,value,**kwargs):
    if "tbname" in kwargs:        
        if "session" in kwargs:
            tb=db(table=kwargs["tbname"],session=kwargs["session"])
        else:
            tb=db(kwargs["tbname"])
    else:
        tb=gdb
    try:
        response=tb.get_item(
            Key={
                    partkeyid:value
                }
        )
        return response
    except:
        raise

def listTable(**kwargs):
    if "tbname" in kwargs:        
        if "session" in kwargs:
            tb=db(table=kwargs["tbname"],session=kwargs["session"])
        else:
            tb=db(kwargs["tbname"])
    else:
        table=None
        tb=gdb
    try:
        if table != None:
            response=tb.list_tables(ExclusiveStartTableName=table)
        else:
            response=tb.list_tables()
        return response
    except:
        raise

def getObjectS3(file,path,bucket,**kwargs):      
    if "session" in kwargs:
        bk=S3(session=kwargs["session"])
    else:
        bk=gbk
    try:
        key = f'{path}{file}'
        response = bk.get_object(
            Bucket=bucket,
            Key=key
        )
        return response
    except:
        raise

def moveObjectS3(file,bucket,pathFrom,pathDest,**kwargs):
    if "session" in kwargs:
        bk=S3(session=kwargs["session"])
    else:
        bk=gbk
    try:
        key = f'{pathFrom}{file}'
        copy_source = {
            'Bucket': bucket,
            'Key': key
            }
        responseCopy = bk.copy_object(
            Bucket=bucket,
            CopySource= copy_source,
            Key=f'{pathDest}{file}'
        )
        responseDelete = bk.delete_object(
            Bucket=bucket,
            Key= key
        )
        return [responseCopy,responseDelete]
    except:
        raise

def putObjectS3(bucket,pathFile,file,value,**kwargs):
    if "session" in kwargs:
        bk=S3(session=kwargs["session"])
    else:
        bk=gbk
    try:
        key = f'{pathFile}{file}'
        response = bk.put_object(
            Bucket=bucket,
            Key=key,
            Body=value
        )
        return response
    except:
        raise

def listObjectV2(bucket,pathFile,file,**kwargs):
    if "session" in kwargs:
        bk=S3(session=kwargs["session"])
    else:
        bk=gbk
    try:
        response = bk.list_objects_v2(
            Bucket=bucket,
            Prefix=f'{pathFile}{file}'
        )
        return response
    except:
        raise

def ObjectS3(bucket,path,file,**kwargs):
    if "session" in kwargs:
        bk=S3(session=kwargs["session"])
    else:
        bk=gbkResourse
    try:
        key = f'{path}{file}'
        response = bk.Object(bucket,key)
        return response
    except:
        raise

def deleteObjectS3(bucket,path,file,**kwargs):
    if "session" in kwargs:
        bk=S3(session=kwargs["session"])
    else:
        bk=gbk
    try:
        key = f'{path}{file}'
        response = bk.delete_object(
            Bucket=bucket,
            Key= key
        )
        return response
    except:
        raise

def copyObjectS3(bucket,path,file,**kwargs):
    if "session" in kwargs:
        bk=S3(session=kwargs["session"])
    else:
        bk=gbk
    try:
        key = f'{path}{file}'
        copy_source = {
            'Bucket': bucket,
            'Key': key
            }
        response = bk.copy_object(
            Bucket=bucket,
            CopySource= copy_source,
            Key=key
        )
        return response
    except:
        raise

def uploadObjectS3(file,bucket,contentType,fileName=None,**kwargs):
    if "session" in kwargs:
        bk=S3(session=kwargs["session"])
    else:
        bk=gbk
    try:
        response = bk.upload_file(file,bucket,Key=fileName,ExtraArgs={'ContentType': f'{contentType}'})
        return response
    except:
        raise


def invokeLambda(functionName,payload,**kwargs):
    if "session" in kwargs:
        lk=Lambda(session=kwargs["session"])
    else:
        lk=lik
    try:
        response = lk.invoke(
            FunctionName=functionName,
            InvocationType='RequestResponse',
            Payload=json.dumps(payload),
            LogType='Tail'
            )
        return response
    except:
        raise

def scanTable(filter,operator,value,**kwargs):
    if "tbname" in kwargs:        
        if "session" in kwargs:
            tb=db(table=kwargs["tbname"],session=kwargs["session"])
        else:
            tb=db(kwargs["tbname"])
    else:
        table=None
        tb=gdb
    try:
        validOperator = {
            'lt' : Attr('#cd').lt(':val'),
            'le' : Attr('#cd').lte(':val'),
            'eq': Attr('#cd').eq(':val'),
            'ne': Attr('#cd').ne(':val'),
            'ge': Attr('#cd').gte(':val'),
            'gt': Attr('#cd').gt(':val')
        }
        expression = validOperator[operator]
        if table != None:
            scan_kwargs={
                'FilterExpression': expression,
                'ExpressionAttributeNames': {"#cd": f"{filter}"},
                'ExpressionAttributeValues': {':val': f"{value}"}
            }
            start_key = None
            scan_kwargs['ExclusiveStartKey'] = start_key
            response=tb.scan(**scan_kwargs)
        return response
    except:
        raise

def listEventSourceMappings(function_name,**kwargs):
    if "session" in kwargs:
        lk=Lambda(session=kwargs["session"])
    else:
        lk=lik
    try:
        response = lk.list_event_source_mappings(FunctionName=function_name)
        return response
    except:
        raise

def updateEventSourceMappings(function_name,uuid,**kwargs):
    if "session" in kwargs:
        lk=Lambda(session=kwargs["session"])
    else:
        lk=lik
    if "batchSize" in kwargs:
        new_batch_size=kwargs["batchSize"]
    else:
        new_batch_size=10
    try:
        response = lk.update_event_source_mapping(
            UUID=uuid,
            FunctionName=function_name,
            BatchSize=new_batch_size
        )
        return response
    except:
        raise

def getSecretManager(secretId,**kwargs):
    if "session" in kwargs:
        sm=SecretMgr(session=kwargs["session"])
    else:
        sm=smk
    try:
        response = sm.get_secret_value(
                SecretId=secretId
            )
        return response
    except:
        raise

def sendMessageSQS(queueUrl,message,delaySeconds,**kwargs):
    if "session" in kwargs:
        sqs=SQS(session=kwargs["session"])
    else:
        sqs=sqsk
    try:
        response = sqs.send_message(
                    QueueUrl=queueUrl,
                    DelaySeconds=delaySeconds,
                    MessageBody=message
                )
        print("Se envía SQS correctamente.")
        return response
    except:
        raise

def cognitoUpdateAttributes(userPoolId,username,listUserAttributes,**kwargs):
    if "session" in kwargs:
        cognito=Cognito(session=kwargs["session"])
    else:
        cognito=cgnk
    try:
        response = cognito.admin_update_user_attributes(
                UserPoolId=userPoolId,
                Username=username,
                UserAttributes=listUserAttributes
            )
        return response
    except:
        raise
        #name1 = ''
        #value1 = ''
        #name2 = ''
        #value2 = ''
        #nameN = ''
        #valueN = ''
        #dictUserAttributes = [
        #    {
        #        'Name': name1,
        #        'Value': value1
        #    },
        #    {
        #        'Name': name2,
        #        'Value': value2
        #    },
        #    {
        #        'Name': nameN,
        #        'Value': valueN
        #    }
        #]

def cognitoDisableUser(userPoolId,username,**kwargs):
    if "session" in kwargs:
        cognito=Cognito(session=kwargs["session"])
    else:
        cognito=cgnk
    try:
        response = cognito.admin_disable_user(
            UserPoolId=userPoolId,
            Username=username,
        )
        return response
    except:
        raise

def cognitoListUsers(userPoolId,dictAttributes,filters,**kwargs):
    if "session" in kwargs:
        cognito=Cognito(session=kwargs["session"])
    else:
        cognito=cgnk
    try:
        response = cognito.list_users(
            UserPoolId=userPoolId,
            AttributesToGet=dictAttributes,
            Filter=filters
        )
        return response
    except:
        raise

def cognitoEnableUser(userPoolId,username,**kwargs):
    if "session" in kwargs:
        cognito=Cognito(session=kwargs["session"])
    else:
        cognito=cgnk
    try:
        response = cognito.admin_enable_user(
            UserPoolId=userPoolId,
            Username=username,
        )
        return response
    except:
        raise

def updateWithExpression(partkeyid,valueKey,**kwargs):
    if "tbname" in kwargs:        
        if "session" in kwargs:
            tb=db(table=kwargs["tbname"],session=kwargs["session"])
        else:
            tb=db(kwargs["tbname"])
    else:
        tb=gdb
    datenow=datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]+'Z'
    at=""
    ut=""
    ax=0
    index={}
    valueIndex={}
    eAN={}
    listaExpresionesNames=('#ab','#cd','#ef','#gh','#ij','#kl','#mn','#op','#qr','#st')
    listaExpresionesValues=(':a',':c',':e',':g',':i',':k',':m',':o',':q',':s')
    kwargs.pop('tbname',None)
    kwargs.pop('session',None)
    EAVal='{'+at+'":zz":"'+datenow+'"}'
    EAVal = json.loads(EAVal)
    eAN={'#ud': 'UpdatedDate'}
    for key in kwargs.items():
        index[ax]=key[0]
        idx = listaExpresionesNames[ax]
        eAN[idx]=index[ax]
        ax+=1
    ax=0
    for key, value in kwargs.items():
        valueIndex[ax]=value
        valIndx = listaExpresionesValues[ax]
        EAVal[valIndx]=valueIndex[ax]
        ax+=1
    ax=0
    listaValoresEAV=[]
    for keyV, valueV in EAVal.items():
        listaValoresEAV.append(keyV)
    for key, value in eAN.items():
        if ax >= 1:
            ut=ut+", "+key+"="f"{listaValoresEAV[ax]}"
        else:
            ut=ut+key+"="f"{listaValoresEAV[ax]}"
        ax+=1    
    UExp="set "+ut
    try:
        response = tb.update_item(        
                Key={
                    partkeyid:valueKey
                },
                UpdateExpression=UExp,
                ExpressionAttributeNames=eAN,
                ExpressionAttributeValues=EAVal,
                ReturnValues="UPDATED_NEW"
            )
        pprint(response)
    except:
        raise
