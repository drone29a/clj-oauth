(ns oauth.client-twitter-test
  (:refer-clojure :exclude [key])
  (:require [oauth.client :as oc]
            [oauth.signature :refer [oauth-params signature-methods]])
  (:use clojure.test)
  (:import [clojure.lang ExceptionInfo])
  (:load "twitter_keys"))

(def consumer (oc/make-consumer key
                                secret
                                "https://api.twitter.com/oauth/request_token"
                                "https://api.twitter.com/oauth/access_token"
                                "https://api.twitter.com/oauth/authorize"
                                :hmac-sha1))
(deftest
    #^{:doc "Test requesting a token from Twitter.
            Considered to pass if no exception is thrown."}
  request-token-success-test
  (is (= 200
         (:status (oc/request-token consumer)))
      "Twitter has regarded your application as web application.")
  (is (= 200
         (:status (oc/request-token consumer "http://localhost/")))
      "Twitter has regarded your application as desktop application."))

(deftest
  ^{:doc "Test requesting a token from Twitter.
         Considered to pass if some exception is thrown."}
  request-token-error-test
  (testing "When consumer has not been passed."
    (is (thrown-with-msg? ExceptionInfo
                          #"clj-http: status 400"
                          (oc/request-token nil))
        "Calling request_token has been passed but header has not set.")
    (is (thrown-with-msg? ExceptionInfo
                          #"clj-http: status 400"
                          (oc/request-token nil "http://localhost/"))
        "Calling request_token has been passed but header has not set."))
  (testing "When consumer is passed but oauth_timestamp is invalid. (timestamp = -1)"
    (with-redefs [oauth-params (fn
                                  ([consumer nonce _]
                                   {:oauth_consumer_key (:key consumer)
                                    :oauth_signature_method (sig/signature-methods (:signatue-method consumer))
                                    :oauth_timestamp -1
                                    :oauth_nonce nonce
                                    :oauth_version "1.0"})
                                  ([consumer nonce _ token]
                                   (assoc (oauth-params consumer nonce nil)
                                          :oauth_token token))
                                  ([consumer nonce _ token verifier]
                                   (assoc (oauth-params consumer nonce nil token)
                                          :oauth_verifier verifier)))]
      (is (thrown-with-msg? ExceptionInfo
                            #"clj-http: status 401"
                            (oc/request-token consumer))
          "oauth_timestamp has been passed but is invalid.")
      (is (thrown-with-msg? ExceptionInfo
                            #"clj-http: status 401"
                            (oc/request-token consumer "http://localhost/"))
          "oauth_timestamp has been passed but is invalid.")))
  (testing "When consumer key, Consumer secret or both is incorrect:"
    (let [request-uri "https://api.twitter.com/oauth/request_token"
          access-uri "https://api.twitter.com/oauth/access_token"
          authorize-uri "https://api.twitter.com/oauth/authorize"
          signature-method :hmac-sha1]
      (is (thrown-with-msg? ExceptionInfo
                            #"clj-http: status 401"
                            (oc/request-token (oc/make-consumer nil
                                                                nil
                                                                request-uri
                                                                access-uri
                                                                authorize-uri
                                                                signature-method)))
          "Request Token has been responded but Consumer Key and Consumer Secret are nil.")
      (is (thrown-with-msg? ExceptionInfo
                            #"clj-http: status 401"
                            (oc/request-token (oc/make-consumer key
                                                                nil
                                                                request-uri
                                                                access-uri
                                                                authorize-uri
                                                                signature-method)))
          "Request Token has been responded but Consumer Secret is nil.")
      (is (thrown-with-msg? ExceptionInfo
                            #"clj-http: status 401"
                            (oc/request-token (oc/make-consumer nil
                                                                secret
                                                                request-uri
                                                                access-uri
                                                                authorize-uri
                                                                signature-method)))
          "Request Token has been responded but Consumer Key is nil."))))

(deftest
    #^{:doc "Considered to pass if no exception is thrown."}
  user-approval-uri
  (is (instance? String (oc/user-approval-uri consumer (:oauth_token (oc/request-token consumer))))))

#_(deftest
    #^{:doc "Considered to pass if no exception is thrown."}
  access-token
  (let [request-token (oc/request-token consumer)]
    (oc/access-token consumer request-token ...verifier...)))
