(ns oauth.digest
  (:import (javax.crypto Mac)
	   (javax.crypto.spec SecretKeySpec)
	   [java.security Signature KeyStore]
	   [org.apache.commons.codec.binary Base64]
	   [java.net URLDecoder])
  (:require [clojure.java.io :as io]
	    [clojure.string :as str]
	    [oauth.keystore :as keystore]))

(defn- encode [data]
  (String. (Base64/encodeBase64 data) "UTF-8"))

(defn hmac 
  "Calculate HMAC signature for given data."
  [^String key ^String data]
  (let [hmac-sha1 "HmacSHA1"
        signing-key (SecretKeySpec. (.getBytes key) hmac-sha1)
        mac (doto (Mac/getInstance hmac-sha1) (.init signing-key))]
    (encode (.doFinal mac (.getBytes data)))))

(defn- extract-uri [data]
  (-> data
      (str/split #"&")
      second
      (URLDecoder/decode "UTF-8")))

(defn rsa
  "Calculate RSA signature for given data."
  [^String key ^String data]
  (if-let [signature-generator (keystore/signature-generator (extract-uri data))]
    (do
      (.update signature-generator (.getBytes data))
      (encode (.sign signature-generator)))
    (throw (IllegalStateException. "Cannot calculate rsa signature - no keystore registered. See oauth.keystore/register-rsa-signature-generator-key."))))
