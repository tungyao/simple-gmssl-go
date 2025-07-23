# simple-gmssl-go
用于解决官方的cgo库,不能导出der的问题  

**实现了两个常用的加密方式 `sm2` `sm4`**


使用该版本[GmSSL](https://github.com/guanzhi/GmSSL/tree/34fa519dc0f94a9a3995d9daf09c84cdac37abd8) , 需使用cgo进行编译

__示例__:

```golang
// sm2

var sm2 = new(Sm2)
// 生成密钥
sm2.GenerateKey()
// 导出
pri,pub :=sm2.Export()

// 导入
sm2.ImportPri([]byte)
sm2.ImportPub([]byte)

// 加密数据
out, err := sm2.Encrypt([]byte)

// 解密
out2, err := sm2.Decrypt(out)
```



```golang
// sm4
var data = []byte("123123")
var key = []byte("oCD5gA(v6Gh5JoU)t!##hW44x@7)s@X$") // 长度需为16的倍数
var iv =  []byte("1231231231231231") // 长度需为16
out, err := sm4.Encrypt(data, key, iv)

out2, err :=sm4.Decrypt(out,key,iv)
```