//分段加密方法
JSEncrypt.prototype.encryptLong = function (string) {  
  var k = this.getKey(),
  maxLength = (((k.n.bitLength()+7)>>3)-11);

  try {
    var lt = "",
    ct = "";

    if (string.length > maxLength) {
      lt = string.match(/.{1,50}/g);
      lt.forEach(entry => {
        var t1 = k.encrypt(entry);
        ct += t1 ;
      });
      return hex2b64(ct);
    }
    var t = k.encrypt(string),
    y = hex2b64(t);
    return y;
  } catch (ex) {
    return ex;
  }
};

//分段解密方法
JSEncrypt.prototype.decryptLong = function (string) {    
  var k = this.getKey(),
  maxLength = (((k.n.bitLength()+7)>>3)-11);
   
  try {    
    var ct = '';  
    string = b64tohex(string)
    if (string.length > maxLength) {        
      var lt = string.match(/.{1,256}/g);  
      lt.forEach(function(entry) {          
        var t1 = k.decrypt(entry);     
        ct += t1;
      });
      return ct;   
    }      
    var y = k.decrypt(b64tohex(string));      
    return y;
  } catch (ex) {
    return ex;
  }  
};

Vue.prototype.$getCode = function(key, str) {
  var encrypt = new JSEncrypt()
  encrypt.setPublicKey(key)
  var data = encrypt.encrypt(str)
  return data
}

Vue.prototype.$deCode = function(key, str) {
  var encrypt = new JSEncrypt()
  encrypt.setPrivateKey(key)
  var data = encrypt.decrypt(str)
  return data
}

//分段加密
Vue.prototype.$getLongCode = function(key, str) {
  var encrypt = new JSEncrypt()
  encrypt.setPublicKey(key)
  var data = encrypt.encryptLong(str)
  return data
}

//分段解密
Vue.prototype.$deLongCode = function(key, str) {
  var decryptLong = new JSEncrypt()
  decryptLong.setPrivateKey(key)
  var data = decryptLong.decryptLong(str)
  return /^{.+}$/g.test(data) && JSON.parse(data) || data
}