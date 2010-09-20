(ns oauth.client-term-test
  (:require [oauth.client :as oc])
  (:use clojure.test))

(def consumer (oc/make-consumer "key"
                                "secret"
                                "http://term.ie/oauth/example/request_token.php"
                                "http://term.ie/oauth/example/access_token.php"
                                "http://term.ie/oauth/example/echo_api.php"
                                :hmac-sha1))

(deftest
    #^{:doc "Test with http://term.ie server.
            Considered to pass if no exception is thrown."}
  request-token
  (oc/request-token consumer))