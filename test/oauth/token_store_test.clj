(ns oauth.token-store-test
  (:require [oauth.token-store :as store] :reload-all)
  (:use clojure.test))
  
  (deftest  
    #^{:doc "get consumer from memory"}
    consumer-get
    (is (= (store/consumer-get :memory nil) nil))
    (is (= (store/consumer-get :memory "") nil))
  )
  
  (deftest  
    #^{:doc "store consumer in memory"}
    consumer-put
    (let [consumer (store/consumer-put :memory {:key "consumer" :secret "ssh"}) ]
      (is (= consumer {:key "consumer" :secret "ssh"}))
      (is (= (store/consumer-get :memory "consumer") {:key "consumer" :secret "ssh"}))
      )
  )
  
  (deftest  
    #^{:doc "get request-token from memory"}
    request-token-get
    (is (= (store/request-token-get :memory nil) nil))
    (is (= (store/request-token-get :memory "") nil))
  )

  (deftest  
    #^{:doc "store request-token in memory"}
    request-token-put
    (let [request-token (store/request-token-put :memory {:token "request-token" :secret "ssh"}) ]
      (is (= request-token {:token "request-token" :secret "ssh"}))
      (is (= (store/request-token-get :memory "request-token") {:token "request-token" :secret "ssh"}))
      )
  )

  (deftest  
    #^{:doc "revoke request-token in memory"}
    request-token-revoke
    (let [request-token (store/request-token-put :memory {:token "request-token" :secret "ssh"}) ]
      (do
        (store/request-token-revoke :memory "request-token")
        (is (= (store/request-token-get :memory "request-token") nil))
        )
      )
  )
  
  (deftest  
    #^{:doc "get access-token from memory"}
    access-token-get
    (is (= (store/access-token-get :memory nil) nil))
    (is (= (store/access-token-get :memory "") nil))
  )

  (deftest  
    #^{:doc "store access-token in memory"}
    access-token-put
    (let [access-token (store/access-token-put :memory {:token "access-token" :secret "ssh"}) ]
      (is (= access-token {:token "access-token" :secret "ssh"}))
      (is (= (store/access-token-get :memory "access-token") {:token "access-token" :secret "ssh"}))
      )
  )
  
  (deftest  
    #^{:doc "revoke access-token in memory"}
    access-token-revoke
    (let [access-token (store/access-token-put :memory {:token "access-token" :secret "ssh"}) ]
      (do
        (store/access-token-revoke :memory "access-token")
        (is (= (store/access-token-get :memory "access-token") nil))
        )
      )
  )
