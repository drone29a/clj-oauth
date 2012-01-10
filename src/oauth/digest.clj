(ns oauth.digest
  (:import (javax.crypto Mac)
	   (javax.crypto.spec SecretKeySpec)
	   [java.security Signature KeyStore])
  (:require [clojure.java.io :as io]))

(defn hmac 
  "Calculate HMAC signature for given data."
  [^String key ^String data]
  (let [hmac-sha1 "HmacSHA1"
        signing-key (SecretKeySpec. (.getBytes key) hmac-sha1)
        mac (doto (Mac/getInstance hmac-sha1) (.init signing-key))]
    (String. (org.apache.commons.codec.binary.Base64/encodeBase64 
              (.doFinal mac (.getBytes data)))
             "UTF-8")))

(defn rsa
  "Calculate RSA signature for given data."
  [^String key ^String data]
  (let [algorithm-name "SHA1WithRSA"
	keystore (doto (KeyStore/getInstance (KeyStore/getDefaultType))
		   (.load (io/input-stream "test-resources/fake-keys/keystore.ImportKey") (.toCharArray "importkey")))
	private-key (.. keystore (getKey "importkey" (.toCharArray "importkey")))
	signature-generator (doto (Signature/getInstance algorithm-name)
			      (.initSign private-key))]
    (.update signature-generator (.getBytes data))
    (String. (org.apache.commons.codec.binary.Base64/encodeBase64 
              (.sign signature-generator))
             "UTF-8")))