(ns oauth.digest
  (:import (javax.crypto Mac)
	   (javax.crypto.spec SecretKeySpec)
	   [java.security Signature KeyStore]
	   [org.apache.commons.codec.binary Base64])
  (:require [clojure.java.io :as io]))

(def ^{:dynamic true :private true} *signature-generator-factory*)

(defn- encode [data]
  (String. (Base64/encodeBase64 data) "UTF-8"))

(defn hmac 
  "Calculate HMAC signature for given data."
  [^String key ^String data]
  (let [hmac-sha1 "HmacSHA1"
        signing-key (SecretKeySpec. (.getBytes key) hmac-sha1)
        mac (doto (Mac/getInstance hmac-sha1) (.init signing-key))]
    (encode (.doFinal mac (.getBytes data)))))

(defn get-signature-generator-factory
  "Takes a description of a key in a keystore, and returns a function
that can be passed to the rsa function as the source of the key used
in the signing process."
  [keystore-path keystore-password key-alias key-password]
  (with-open [keystore-stream (io/input-stream keystore-path)]
    (let [algorithm-name "SHA1WithRSA"
	  keystore (doto (KeyStore/getInstance (KeyStore/getDefaultType))
		     (.load keystore-stream (.toCharArray keystore-password)))
	  private-key (.. keystore (getKey key-alias (.toCharArray key-password)))]
      #(doto (Signature/getInstance algorithm-name)
	 (.initSign private-key)))))

(defn initialise-signature-generator [keystore-path keystore-password key-alias key-password]
  "Initialises the global signature generation factory so the rsa
function can be called with the same api as the hmac one."
  (def ^{:dynamic true :private true}
       *signature-generator-factory*
       (get-signature-generator-factory keystore-path keystore-password key-alias key-password)))

(defn rsa
  "Calculate RSA signature for given data."
  ([^String key ^String data]
     (rsa key data *signature-generator-factory*))
  ([^String key ^String data ^clojure.lang.IFn signature-generator-factory]
     (let [^Signature signature-generator (signature-generator-factory)]
       (.update signature-generator (.getBytes data))
       (encode (.sign signature-generator)))))
