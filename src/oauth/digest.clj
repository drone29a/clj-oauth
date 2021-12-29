(ns oauth.digest
  (:import (javax.crypto Mac)
           (javax.crypto.spec SecretKeySpec)))

(defn hmac-sign
  "Calculate HMAC signature for given data."
  [^String key ^String data ^String hmac-algo]
  (let [signing-key (SecretKeySpec. (.getBytes key) hmac-algo)
        mac (doto (Mac/getInstance hmac-algo) (.init signing-key))]
    (String. (org.apache.commons.codec.binary.Base64/encodeBase64
               (.doFinal mac (.getBytes data)))
             "UTF-8")))
