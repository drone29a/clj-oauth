(ns
    #^{:author "Matt Revelle"
       :doc "OAuth client library for Clojure."}
  oauth.signature
  (:import org.apache.commons.codec.binary.Base64
           org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter)
  (:require [oauth.digest :as digest])
  (:use [clojure.string :only [join]]))

(declare rand-str
         base-string
         sign
         url-encode
         oauth-params)

(defn- named? [a]
  (instance? clojure.lang.Named a))

(defn as-str [a]
  (if (named? a)
    (name a)
    (str a)))

(def secure-random (delay (java.security.SecureRandom/getInstance "SHA1PRNG")))

(defn rand-str
  "Random string for OAuth requests."
  [length]
  (. (new BigInteger (int (* 5 length)) ^java.util.Random @secure-random) toString 32))

(defn msecs->secs
  "Convert milliseconds to seconds."
  [millis]
  (int (/ millis 1000)))

(def signature-methods {:hmac-sha1 "HMAC-SHA1"
                        :hmac-sha256 "HMAC-SHA256"
                        :rsa-sha1 "RSA-SHA1"
                        :plaintext "PLAINTEXT"})

(defn url-form-encode [params]
  (join "&" (map (fn [[k v]]
                   (str (url-encode (as-str k))
                        "=" (url-encode (as-str v)))) params )))
(defn base-string
  ([method base-url c t params]
     (base-string method base-url
                  (assoc params
                    :oauth_consumer_key (:key c)
                    :oauth_token (:token t)
                    :oauth_signature_method (or (params :oauth_signature_method)
                                                (signature-methods (:signature-method c)))
                    :oauth_version "1.0")))
  ([method base-url params]
     (join "&" [method
                (url-encode base-url)
                (url-encode (url-form-encode (sort params)))])))

(defmulti sign
  "Sign a base string for authentication."
  {:arglists '([consumer base-string & [token-secret]])}
  (fn [c & r] (:signature-method c)))

(defmethod sign :hmac-sha1
  [c base-string & [token-secret]]
  (let [key (str (url-encode (:secret c)) "&" (url-encode (or token-secret "")))]
    (digest/hmac-sign key base-string "HmacSHA1")))

(defmethod sign :hmac-sha256
  [c base-string & [token-secret]]
  (let [key (str (url-encode (:secret c)) "&" (url-encode (or token-secret "")))]
    (digest/hmac-sign key base-string "HmacSHA256")))

(defmethod sign :plaintext
  [c base-string & [token-secret]]
  (str (url-encode (:secret c)) "&" (url-encode (or token-secret ""))))

(def ^:private pem-converter
  (doto (JcaPEMKeyConverter.)
    (.setProvider "BC")))

(defmethod sign :rsa-sha1
  [c ^String base-string & [token-secret]]
  (java.security.Security/addProvider
    (org.bouncycastle.jce.provider.BouncyCastleProvider.))
  (let [key-pair (-> (:secret c)
                     java.io.StringReader.
                     org.bouncycastle.openssl.PEMParser.
                     .readObject)
        private-key (-> ^JcaPEMKeyConverter pem-converter
                        (.getKeyPair key-pair)
                        .getPrivate)
        signer (doto (java.security.Signature/getInstance "SHA1withRSA" "BC")
                 (.initSign private-key (java.security.SecureRandom.))
                 (.update (.getBytes base-string)))
        raw-sig (.sign signer)]
    (String. (Base64/encodeBase64 raw-sig))))

(defn verify [sig c base-string & [token-secret]]
  (let [token-secret (url-encode (or token-secret ""))]
    (= sig (sign c base-string token-secret))))

(defn url-encode
  "The java.net.URLEncoder class encodes for application/x-www-form-urlencoded, but OAuth
requires RFC 3986 encoding."
  [s]
  (-> (java.net.URLEncoder/encode s "UTF-8")
      (.replace "+" "%20")
      (.replace "*" "%2A")
      (.replace "%7E" "~")))

(defn url-decode
  "The java.net.URLEncoder class encodes for application/x-www-form-urlencoded, but OAuth
requires RFC 3986 encoding."
  [s]
  (java.net.URLDecoder/decode s "UTF-8"))

(defn oauth-params
  "Build a map of parameters needed for OAuth requests."
  ([consumer nonce timestamp]
     {:oauth_consumer_key (:key consumer)
      :oauth_signature_method (signature-methods (:signature-method consumer))
      :oauth_timestamp timestamp
      :oauth_nonce nonce
      :oauth_version "1.0"})
  ([consumer nonce timestamp token]
     (assoc (oauth-params consumer nonce timestamp)
       :oauth_token token))
  ([consumer nonce timestamp token verifier]
     (assoc (oauth-params consumer nonce timestamp token)
       :oauth_verifier (str verifier))))
