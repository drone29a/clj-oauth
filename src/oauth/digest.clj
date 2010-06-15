(ns oauth.digest
  (:import (javax.crypto Mac)
           (javax.crypto.spec SecretKeySpec)))

(defn hmac 
  "Calculate HMAC signature for given data."
  [^String key ^String data]
  (let [hmac-sha1 "HmacSHA1"
        signing-key (SecretKeySpec. (.getBytes key) hmac-sha1)
        mac (doto (Mac/getInstance hmac-sha1) (.init signing-key))]
    (String. (org.apache.commons.codec.binary.Base64/encodeBase64 
              (.doFinal mac (.getBytes data)))
             "UTF-8")))