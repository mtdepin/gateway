import requests
import pytest
import json
import yaml
import time
import os
import colorama

class Test_object:

    #全局变量
    bucketurl = "https://console.dss.mty.wang"
    content_type="application/json"
    # 上传文件的本地路径

    # windows 文件路径
    # objectPath = "F:\\Source\\ImageSource\\jpg\\招财猫.jpg"

    # linux 文件路径
    objectPath = "./cicd/images/招财猫.jpg"

    # 获取文件名
    filename = os.path.basename(objectPath)

    #web登录
    def test_list_login(self):
        login_body={
            "userName":"yinyi3",
            "password":"UoeT144cxFc6k5Ec4xssmDdMohAHCPVHIwcaDU8vvB3MJwTnhzGqSah+OlWWqN/rc3K8E2d5Ktetw5qpjCUi6YF0JfxsIpKCGsa0fp8Kfl30QYA6z9lu0wIpKBS8GhT8hnNZIUFA/iPv1QhVA1HbljX/7a2uGiqqNXexzNyvmomNlhjJXUKnpruNYlzc0WpQB96uxiHB+KnZlozi5lSdJl6Scbesm+fAPqcfw6Ag/nXzm4We7p0Tt8SGwQns3yG6qwiStaZIjnWvBmx8lLqIYeVL1+v7v4hiFG93QIrA5C2J2lZEXc/WDSVDwM3EsktKV+mLV679xspC72ztY1nyjg=="
        }
        headers = {
            "Content-Type": f"{self.content_type}"
        };
        response = requests.post(self.bucketurl+"/api/user/login",data=json.dumps(login_body),headers=headers)
        print(response.json())
        print("全局token的值为:"+response.json()["data"]["token"])
        token = response.json()["data"]["token"]
        user_id = response.json()["data"]["id"]
        #把token值写入到yaml里
        self.setToken(token)
        #把id值写入到yaml里
        self.setIdYaml(user_id)
        print("yaml值写入成功")
        print("---------------------------------------------")
        time.sleep(2)   #睡2秒


    # 查询桶列表数据
    def test_list_bucket(self):
        yamlGetValue = self.getToken()
        print("全局token的值为："+yamlGetValue)
        headers = {
            "token": f"{yamlGetValue}",
            "Content-Type": f"{self.content_type}"
        };

        # 调用查询桶接口
        response = requests.post(self.bucketurl+"/api/bucket/list", data={}, headers=headers)
        print(response.json())
        print("查询该账号下所有桶数据成功！")
        print("---------------------------------------------")


    #查询桶名称是否存在
    def test_bucket_exists(self):
        yamlGetValue = self.getToken()
        print("全局token的值为：" + yamlGetValue)
        headers = {
            "token": f"{yamlGetValue}",
            "Content-Type": f"{self.content_type}"
        };
        exists_body={
            "bucketName": "dfbb"
        }
        # 调用查询桶接口
        #方法一
        response = requests.post(self.bucketurl + "/api/bucket/exists", data=json.dumps(exists_body), headers=headers)
        #方法二
        #response  = RequestsUtil().send_request("post",self.bucketurl + "/api/bucket/exists",json.dumps(exists_body),headers=headers)
        print(response.json())
        querystate = json.dumps(response.json()["data"])
        print("查询桶名称是否存在状态为："+querystate)
        if querystate=='true':
            print(colorama.Fore.RED + "★★★该桶名称已存在呢" + colorama.Fore.BLACK)
        else:
            print("该桶名称不存在，可以创建该桶呢！")
        print("---------------------------------------------")


    #删除桶
    def test_bucket_delete(self):
        yamlGetValue = self.getToken()
        print("全局token的值为：" + yamlGetValue)
        headers = {
            "token": f"{yamlGetValue}",
            "Content-Type": f"{self.content_type}"
        };
        delete_body = {
            "bucketName": "heihei"
        }
        response = requests.post(self.bucketurl + "/api/bucket/delete", data=json.dumps(delete_body),
                                 headers=headers)
        print(response.json())
        status = json.dumps(response.json()["success"])
        print("查询桶状态为："+status)
        if status =='false':
            print(colorama.Fore.RED + "★★★" +response.json()["message"] + colorama.Fore.BLACK)
        else:
            print(response.json()["message"])
        print("---------------------------------------------")


    #创建桶
    def test_bucket_create(self):
        yamlGetValue = self.getToken()
        print("全局token的值为：" + yamlGetValue)
        headers = {
            "token": f"{yamlGetValue}",
            "Content-Type": f"{self.content_type}"
        };
        create_body={
            "bucketName":"dfbb",
            "objectLocking":False,
            "regionId":"mos-huadong-hangzhou",
            "status":"Suspended",
            "storageClass":"STANDARD",
            "tags": [{"key":"","value":""}]
        }
        # 调用查询桶接口
        response = requests.post(self.bucketurl + "/api/bucket/create", data=json.dumps(create_body), headers=headers)
        print(response.json())
        print(response.json()["message"])
        print("---------------------------------------------")


    #桶详情
    def test_bucket_detail(self):
        yamlGetValue = self.getToken()
        print("全局token的值为：" + yamlGetValue)
        headers = {
            "token": f"{yamlGetValue}",
            "Content-Type": f"{self.content_type}"
        };
        detail_body={
            "bucketName": "dfbb"
        }
        response = requests.post(self.bucketurl+"/api/bucket/detail",data=json.dumps(detail_body),headers=headers)
        print(response.json())
        print("桶详情查询成功")
        print("--------------------------------------------")


    #创建文件目录
    def test_directory_create(self):
        yamlGetValue = self.getToken()
        print("全局token的值为：" + yamlGetValue)
        headers = {
            "token": f"{yamlGetValue}",
            "Content-Type": f"{self.content_type}"
        };
        directory_body={
            "bucketName":"dfbb",
            "fileName":"yinyy"
        }
        response = requests.post(self.bucketurl+"/api/object/directory/create",data=json.dumps(directory_body),headers=headers)
        print(response.json())
        print("---------------------------------------------")



    #向目录(yinyy)里上传文件  ★★★
    def test_directory_upload(self):
        #获取本地文件路径
        path =self.objectPath
        url = "https://testbd.dss.mty.wang:9000/dfbb//yinyy//"+self.filename
        payload = {'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
                   'X-Amz-Credential': 'BSmJGSqGuYq6tVhhP2gp/20220421/mos-huadong-hangzhou/s3/aws4_request',
                   'X-Amz-Date': '20220421T093746Z',
                   'X-Amz-Expires': '28800',
                   'X-Amz-Signature': '4dd9cada6c81aab809507c2e762ffe71545f99913f98891e682a83ee3612d1e2',
                   'X-Amz-SignedHeaders': 'host'}
        files = [
            ('file', (self.filename, open(path, 'rb'),
                      'application/octet-stream'))
        ]
        headers = {
            'Accept': '*/*',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            'Cookie': '_ga=GA1.1.1111381388.1639561348; _ga_XNGRBER8NV=GS1.1.1645680034.6.0.1645680034.0; _ga_K4Z1WPJFV5=GS1.1.1650508453.35.1.1650509061.0',
            'Origin': 'https://console.dss.mty.wang',
            'Referer': 'https://console.dss.mty.wang/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36',
            'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="100", "Google Chrome";v="100"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"'
        }

        response = requests.request("POST", url, headers=headers, data=payload, files=files)
        print(response.text)
    print("---------------------------------------------")


    #查询桶里的文件详情信息
    def test_file_details(self):
        yamlGetValue = self.getToken()
        print("全局token的值为：" + yamlGetValue)
        headers = {
            "token": f"{yamlGetValue}",
            "Content-Type": f"{self.content_type}"
        };
        detail_body={
            "bucketName":"dfbb",
            "objectName":"yinyy/"+self.filename
        }
        response = requests.get(self.bucketurl+"/api/object/detail?bucket",params=detail_body,headers=headers)
        print(response.json())
        versionId = response.json()["data"]["metadata"]["versionID"]
        print("versionID:"+versionId)
        #把versionId写入到yaml里
        self.setVersionIdYaml(versionId)
        print("---------------------------------------------")




    #下载目录里的文件
    def test_directory_downfile(self):
        yamlGetValue = self.getToken()
        print("全局token的值为：" + yamlGetValue)
        headers = {
            "token": f"{yamlGetValue}",
            "Content-Type": f"{self.content_type}"
        };
        downfile_body={
            "bucketName":"dfbb",
            "objectName":"yinyy/"+self.filename
        }
        response = requests.get(self.bucketurl+"/api/object/download/link",params=downfile_body,headers=headers)
        print(response.json())
        print("下载地址:"+response.json()["data"]["shareLink"])
        print("---------------------------------------------")


    #给文件夹里的文件设置标签 ★
    def test_setFile_tag(self):
        yamlGetValue = self.getToken()
        print("全局token的值为：" + yamlGetValue)
        versionid =self.getVersionIdYaml()
        print("versionid："+versionid)
        headers = {
            "token": f"{yamlGetValue}",
            "Content-Type": f"{self.content_type}"
        };
        tag_body = {
            "bucketName": "dfbb",
            "objectName": "yinyy/"+self.filename,
            "versionId": versionid,
            "tags": [{"key": "4", "value": "4"},
                     {"key": "alert('fuck')", "value": "2"}, {"key": "★", "value": "papapa"},{"key": "僵尸", "value": "唂哈哈只"}]
        }
        response = requests.post(self.bucketurl+"/api/object/tags/put",data=json.dumps(tag_body),headers=headers)
        print(response.json())
        print("---------------------------------------------")


    # 查询桶里（未删除）文件数据
    def test_object_list(self):
        yamlGetValue = self.getToken()
        print("全局token的值为：" + yamlGetValue)
        headers = {
            "token": f"{yamlGetValue}",
            "Content-Type": f"{self.content_type}"
        };
        file_list = {
            "bucketName": "dfbb",
            "recursive": False,
            "size": "10",
            "del": False
        }
        response = requests.get(self.bucketurl + "/api/object/list", params=file_list, headers=headers)
        print(response.json())
        print("---------------------------------------------")


    # 查询桶里（已删除）文件数据
    def test_object_delete_list(self):
        yamlGetValue = self.getToken()
        print("全局token的值为：" + yamlGetValue)
        headers = {
            "token": f"{yamlGetValue}",
            "Content-Type": f"{self.content_type}"
        };
        file_list = {
            "bucketName": "dfbb",
            "size": "10",
            "del": True
        }
        response = requests.get(self.bucketurl + "/api/object/list", params=file_list, headers=headers)
        print(response.json())
        print("---------------------------------------------")


    #分享桶里文件夹的文件
    def test_bucket_sharefiles(self):
        yamlGetValue = self.getToken()
        print("全局token的值为：" + yamlGetValue)
        headers = {
            "token": f"{yamlGetValue}",
            "Content-Type": f"{self.content_type}"
        };
        #response = requests.get(self.bucketurl+"/api/object/share?bucketName=dfbb&objectName=yinyy/月夜.png&expiration=600&versionId=",headers=headers)
        response = requests.get(self.bucketurl+"/api/object/share?bucketName=dfbb&objectName=yinyy/"+self.filename+"&expiration=600&versionId=",headers=headers)
        print(response.json())
        print("---------------------------------------------")


    #删除目录里的文件
    # def test_file_delete(self):
    #     yamlGetValue = self.getToken()
    #     print("全局token的值为：" + yamlGetValue)
    #     headers = {
    #         "token": f"{yamlGetValue}",
    #         "Content-Type": f"{self.content_type}"
    #     };
    #     fiel_delete_body={
    #         "bucketName": "dfbb",
    #         "versionDel": False,
    #         "object": [{"objectName": "yinyy/"+self.filename}]
    #     }
    #     response = requests.post(self.bucketurl+"/api/object/delete",data=json.dumps(fiel_delete_body),headers=headers)
    #     print(response.json())
    #     print(response.json()["message"])
    #     print("---------------------------------------------")


    #删除目录里的文件夹
    def test_directory_delete(self):
        yamlGetValue = self.getToken()
        print("全局token的值为：" + yamlGetValue)
        headers = {
            "token": f"{yamlGetValue}",
            "Content-Type": f"{self.content_type}"
        };
        directory_delete={
            "fileName":"gggg"
        }
        response = requests.delete(self.bucketurl + "/api/object/directory/delete?bucketName=dfbb&fileName="+directory_delete["fileName"],headers=headers)
        print(response.json())
        print(response.json()["message"])
        print("---------------------------------------------")


    #彻底删除文件
    def test_file_thorough_delete(self):
        yamlGetValue = self.getToken()
        print("全局token的值为：" + yamlGetValue)
        headers = {
            "token": f"{yamlGetValue}",
            "Content-Type": f"{self.content_type}"
        };
        thorough_delete_body={
            "bucketName": "dfbb",
            "objectName": ["反诈宣传书.pdf"]
        }
        response = requests.post(self.bucketurl+"/api/object/free",data=json.dumps(thorough_delete_body),headers=headers)
        print(response.json())
        print(response.json()["message"])
        print("---------------------------------------------")


    #彻底删除文件夹
    def test_file_thogough_field(self):
        yamlGetValue = self.getToken()
        print("全局token的值为：" + yamlGetValue)
        headers = {
            "token": f"{yamlGetValue}",
            "Content-Type": f"{self.content_type}"
        };
        thorough_field_body = {
            "bucketName": "dfbb",
            "objectName": ["test2/"]
        }
        response = requests.post(self.bucketurl+"/api/object/free",data=json.dumps(thorough_field_body),headers=headers)
        print(response.json())
        print(response.json()["message"])
        print("---------------------------------------------")


    #取消删除文件
    def test_close_delete_file(self):
        yamlGetValue = self.getToken()
        print("全局token的值为：" + yamlGetValue)
        headers = {
            "token": f"{yamlGetValue}",
            "Content-Type": f"{self.content_type}"
        };
        close_body={
            "bucketName": "dfbb",
            "versionDel": True,
            "deleted": True,
            "object": [{"versionId": "63d3f990bee1427d02faa46e68b40ad7", "objectName": "反诈宣传书2.pdf"}]
        }
        response = requests.post(self.bucketurl+"/api/object/delete",data=json.dumps(close_body),headers=headers)
        print(response.json())
        print(response.json()["message"])
        print("---------------------------------------------")



    #给桶设置标签
    def test_setbucket_tag(self):
        yamlGetValue = self.getToken()
        print("全局token的值为：" + yamlGetValue)
        headers = {
            "token": f"{yamlGetValue}",
            "Content-Type": f"{self.content_type}"
        };
        buckettag_body = {
            "bucketName": "dfbb",
            "tags": [{"key": "☆★★", "value": "222"},
                     {"key": "11", "value": "111"},
                     {"key": "22", "value": "222"},
                     {"key": "33", "value": "333"}]
        }
        response = requests.post(self.bucketurl + "/api/bucket/tags/put", data=json.dumps(buckettag_body),headers=headers)
        print(response.json())
        print("---------------------------------------------")



    #创建svc账号
    def test_create_svc(self):
        yamlGetValue = self.getToken()
        print("全局token的值为：" + yamlGetValue)
        headers = {
            "token": f"{yamlGetValue}",
            "Content-Type": f"{self.content_type}"
        };
        createsvc_body={
            "policy":''
        }
        response = requests.post(self.bucketurl+"/api/user/serviceAccount",data=json.dumps(createsvc_body),headers=headers)
        print(response.json())
        print("---------------------------------------------")


    #查询svc账号list
    def test_svc_list(self):
        yamlGetValue = self.getToken()
        print("全局token的值为：" + yamlGetValue)
        headers = {
            "token": f"{yamlGetValue}",
            "Content-Type": f"{self.content_type}"
        };
        svclist_body={
            "manual": True,
            "throwOnError":True
        }
        response = requests.post(self.bucketurl+"/api/user/serviceAccountList",data=json.dumps(svclist_body),headers=headers)
        print(response.json())
        print("---------------------------------------------")


    #获取该账号下余额
    def test_balance_sum(self):
        yamlGetValue = self.getToken()
        print("全局token的值为：" + yamlGetValue)
        headers = {
            "token": f"{yamlGetValue}",
            "Content-Type": f"{self.content_type}"
        };
        id = self.getIdYaml()
        balance_body={
            "id":id
        }
        response = requests.post(self.bucketurl+"/api/expenses/balance",data=json.dumps(balance_body),headers=headers)
        print(response.json())
        print("---------------------------------------------")


    #查询充值记录
    def test_recharges_list(self):
        yamlGetValue = self.getToken()
        print("全局token的值为：" + yamlGetValue)
        headers = {
            "token": f"{yamlGetValue}",
            "Content-Type": f"{self.content_type}"
        };
        id = self.getIdYaml()
        balance_body = {
            "id": id,
            "page": 1,
            "pageSize": 10
        }
        response = requests.post(self.bucketurl+"/api/expenses/recharges",data=json.dumps(balance_body),headers=headers)
        print(response.json())
        print("---------------------------------------------")


    #查询消费记录
    def test_consumers_list(self):
        yamlGetValue = self.getToken()
        print("全局token的值为：" + yamlGetValue)
        headers = {
            "token": f"{yamlGetValue}",
            "Content-Type": f"{self.content_type}"
        };
        id = self.getIdYaml()
        consumers_body={
            "id": id,
            "page": 1,
            "pageSize": 10
        }
        repsonse = requests.post(self.bucketurl+"/api/expenses/consumers",data=json.dumps(consumers_body),headers=headers)
        print(repsonse.json())
        print("---------------------------------------------")


    #获取用户基本信息
    def test_userdetail(self):
        yamlGetValue = self.getToken()
        print("全局token的值为：" + yamlGetValue)
        headers = {
            "token": f"{yamlGetValue}",
            "Content-Type": f"{self.content_type}"
        };
        id = self.getIdYaml()
        repsonse = requests.get(self.bucketurl + "/api/personal/detail?id="+id,headers=headers)
        print(repsonse.json())
        print("---------------------------------------------")










    #写入到yaml文件里
    def setToken(self,token):
        with open('./test.yaml', 'w', encoding='utf8') as f:
            yaml.dump(token, f)


    #读取yaml里的文件
    def getToken(self):
        with open('./test.yaml', 'r', encoding='utf8') as f:
            data = yaml.load(f, Loader=yaml.Loader)
        return data

    #写入id到yaml文件里
    def setIdYaml(self,id):
        with open('./getValueId.yaml', 'w', encoding='utf8') as f:
            yaml.dump(id, f)

    #读取yaml里的id文件
    def getIdYaml(self):
        with open('./getValueId.yaml', 'r', encoding='utf8') as f:
            data = yaml.load(f, Loader=yaml.Loader)
        return data

    #写入versionId到yaml文件里
    def setVersionIdYaml(self, id):
        with open('./getVersionID.yaml', 'w', encoding='utf8') as f:
            yaml.dump(id, f)

    # 读取yaml里的versionId文件
    def getVersionIdYaml(self):
        with open('./getVersionID.yaml', 'r', encoding='utf8') as f:
            data = yaml.load(f, Loader=yaml.Loader)
        return data

if __name__ == '__main__':
    pytest.main(['-vs'])








