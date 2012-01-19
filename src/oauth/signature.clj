(ns 
    #^{:author "Matt Revelle"
       :doc "OAuth client library for Clojure."} 
  oauth.signature
  (:require [oauth.digest :as digest]
            [clojure.string :as str])
  (:import [java.net URI]))

(declare rand-str
         base-string
         sign
         url-encode
         oauth-params)

(def secure-random (java.security.SecureRandom/getInstance "SHA1PRNG"))

(def ^{:dynamic true} *dump-base-string* false)
(def ^{:dynamic true} *normalize-should-downcase* true)
(def ^{:dynamic true} *exclude-keys-from-basestring* nil)

(defn rand-str 
  "Random string for OAuth requests."
  [length]
  (. (new BigInteger (int (* 5 length)) ^java.util.Random secure-random) toString 32))


(def signature-methods {:hmac-sha1 "HMAC-SHA1"
                        :plaintext "PLAINTEXT"
			:rsa-sha1 "RSA-SHA1"})

(defn url-form-encode [params]
  (str/join "&" (map (fn [[k v]]
                       (str (url-encode (name k)) "=" (url-encode (str v)))) params )))

(defn normalize [url]
  "Normalize the URL before using in the Signature Base String.
   see http://tools.ietf.org/html/rfc5849#section-3.4.1.2"
  (let [uri (URI. url)
	scheme (.getScheme uri)
	host (.getHost uri)
	port (.getPort uri)
	path (.getPath uri)
	hide-port? (or (neg? port)
		       (and (= 80 port) (= "http" scheme))
		       (and (= 443 port) (= "https" scheme)))
	normalized (str scheme "://" host (when-not hide-port? (str ":" port)) path)]
    (if *normalize-should-downcase*
      (.toLowerCase normalized)
      normalized)))

(defn base-string
  ([method base-url c t params]
     (base-string method base-url (assoc params
                                    :oauth_consumer_key (:key c)
                                    :oauth_token (:token t)
                                    :oauth_signature_method (or (params :oauth_signature_method) 
                                                                (signature-methods (:signature-method c)))
                                    :oauth_version "1.0")))
  ([method base-url params]
     (let [params (if (sequential? *exclude-keys-from-basestring*)
		    (apply dissoc params *exclude-keys-from-basestring*)
		    params)
	   base-str (str/join "&" [(.toUpperCase method)
				   (url-encode (normalize base-url))
				   (url-encode (url-form-encode (sort params)))])]
       (when *dump-base-string* (prn (str "base-string:" base-str)))
       base-str)))

(defn- make-sig-key [c token-secret]
  (str (url-encode (:secret c)) "&" (url-encode (or token-secret ""))))

(defmulti sign 
  "Sign a base string for authentication."
  {:arglists '([consumer base-string & [token-secret]])}
  (fn [c & r] (:signature-method c)))

(defmethod sign :hmac-sha1
  [c base-string & [token-secret]]
  (digest/hmac (make-sig-key c token-secret) base-string))

(defmethod sign :plaintext
  [c base-string & [token-secret]]
  (make-sig-key c token-secret))

(defmethod sign :rsa-sha1
  [c base-string & [token-secret]]
  (digest/rsa (make-sig-key c token-secret) base-string))

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
  ([consumer]
     {:oauth_consumer_key (:key consumer)
      :oauth_signature_method (signature-methods (:signature-method consumer))
      :oauth_timestamp (int (/ (System/currentTimeMillis) 1000))
      :oauth_nonce (rand-str 30)
      :oauth_version "1.0"})
  ([consumer token]
     (assoc (oauth-params consumer) 
       :oauth_token token))
  ([consumer token verifier]
     (assoc (oauth-params consumer token)
       :oauth_verifier (str verifier))))

