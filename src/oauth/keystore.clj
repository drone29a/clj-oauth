(ns oauth.keystore
  (:import [java.security Signature KeyStore]
	   [org.apache.commons.codec.binary Base64]
	   [org.apache.http.conn.ssl SSLSocketFactory TrustSelfSignedStrategy AllowAllHostnameVerifier]
	   [org.apache.http.conn.scheme Scheme]
	   ;; [org.apache.http.impl.conn SingleClientConnManager]
	   [org.apache.http.impl.conn.tsccm ThreadSafeClientConnManager]
	   [java.net URI])
  (:require [clojure.java.io :as io]
	    [com.twinql.clojure.http :as http]))

(defonce ^:private registered-connection-managers (atom {}))
(defonce ^:private registered-rsa-signature-generators (atom {}))

(defn- get-host [uri]
  (.getHost (URI. uri)))

(defn create-pkcs-connection-manager
  "Create an connection manager for PKCS oauth connections."
  [keystore-path keystore-password]
  (with-open [keystore-stream (io/input-stream keystore-path)]
    (let [keystore (doto (KeyStore/getInstance (KeyStore/getDefaultType))
		     (.load keystore-stream (.toCharArray keystore-password)))
	  ssl-socket-factory (SSLSocketFactory. "TLS" 
					     keystore
					     keystore-password
					     nil
					     nil
					     (AllowAllHostnameVerifier.))
	  scheme-registry (http/scheme-registry false)]
      (.register scheme-registry (Scheme. "https" ssl-socket-factory 443))
      (ThreadSafeClientConnManager. scheme-registry))))

(defn create-ssl-connection-manager
  "Create an connection manager for PKCS oauth connections."
  []
  (let [ssl-socket-factory (SSLSocketFactory. (TrustSelfSignedStrategy.)
					      (AllowAllHostnameVerifier.))
	scheme-registry (http/scheme-registry false)]
    (.register scheme-registry (Scheme. "https" ssl-socket-factory 443))
    (ThreadSafeClientConnManager. scheme-registry)))

(defn register-connection-manager
  "register a connection mananger for the host in the URI."
  [uri connection-manager]
  (swap! registered-connection-managers assoc (get-host uri) connection-manager))

(defn connection-manager
  "get a registered connection manager, or nil."
  [uri]
  (@registered-connection-managers (get-host uri)))

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

(defn register-rsa-signature-generator-key
  "Initialises the global signature generation factory so the rsa
function can be called with the same api as the hmac one."
  [uri keystore-path keystore-password key-alias key-password]
  (swap! registered-rsa-signature-generators
	 assoc
	 (get-host uri)
	 (get-signature-generator-factory keystore-path keystore-password key-alias key-password)))

(defn signature-generator
  "get a signature generator for the uri, or nil."
  [uri]
  (when-let [factory (@registered-rsa-signature-generators (get-host uri))]
    (factory)))
