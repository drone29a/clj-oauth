(ns oauth.token-store-test
  (:require [oauth.token-store :as store] :reload-all)
  (:use clojure.test))
  
  (deftest  
    #^{:doc "get consumer from memory"}
    get-consumer
    (is (= (store/get-consumer :memory nil) nil))
    (is (= (store/get-consumer :memory "") nil))
  )
  
  (deftest  
    #^{:doc "store consumer in memory"}
    store-consumer
    (let [consumer (store/store-consumer :memory {:key "consumer" :secret "ssh"}) ]
      (is (= consumer {:key "consumer" :secret "ssh"}))
      (is (= (store/get-consumer :memory "consumer") {:key "consumer" :secret "ssh"}))
      )
  )
  
  (deftest
    #^{:doc "Create but don't store a consumer"}
    new-consumer
    (let [consumer (store/new-consumer)]
      (is (not (nil? (consumer :key))))
      (is (not (nil? (consumer :secret))))
      )
    )

  (deftest
    #^{:doc "Create and store a consumer"}
    create-consumer
    (let [consumer (store/create-consumer :memory)]
      (is (not (nil? (consumer :key))))
      (is (not (nil? (consumer :secret))))
      (is (= (store/get-consumer :memory (consumer :key)) consumer))
      )
    )
  
  (deftest  
    #^{:doc "get request-token from memory"}
    get-request-token
    (is (= (store/get-request-token :memory nil) nil))
    (is (= (store/get-request-token :memory "") nil))
  )

  (deftest  
    #^{:doc "store request-token in memory"}
    store-request-token
    (let [request-token (store/store-request-token :memory {:token "request-token" :secret "ssh"}) ]
      (is (= request-token {:token "request-token" :secret "ssh"}))
      (is (= (store/get-request-token :memory "request-token") {:token "request-token" :secret "ssh"}))
      )
  )

  (deftest  
    #^{:doc "revoke request-token in memory"}
    revoke-request-token
    (let [request-token (store/store-request-token :memory {:token "request-token" :secret "ssh"}) ]
      (do
        (store/revoke-request-token :memory "request-token")
        (is (= (store/get-request-token :memory "request-token") nil))
        )
      )
  )

  (deftest
    #^{:doc "Create but don't store a request token"}
    new-request-token
    (let [token (store/new-request-token "http://test.com/callback")]
      (is (not (nil? (token :token))))
      (is (not (nil? (token :secret))))
      (is (not (nil? (token :verifier))))
      (is (= (token :callback_url "http://test.com/callback")))
      )
    (let [token (store/new-request-token "http://test.com/callback" {:scope "http://test.com/calendar"})]
      (is (not (nil? (token :token))))
      (is (not (nil? (token :secret))))
      (is (not (nil? (token :verifier))))
      (is (= (token :callback_url "http://test.com/callback")))
      (is (= (token :scope "http://test.com/calendar")))
      )
    )

  (deftest
    #^{:doc "Create and store a request token"}
    create-request-token
    (let [token (store/create-request-token :memory "http://test.com/callback")]
      (is (not (nil? (token :token))))
      (is (not (nil? (token :secret))))
      (is (not (nil? (token :verifier))))
      (is (= (token :callback_url "http://test.com/callback")))
      (is (= (store/get-request-token :memory (token :token)) token))
      )
    (let [token (store/create-request-token :memory "http://test.com/callback" {:scope "http://test.com/calendar"})]
      (is (not (nil? (token :token))))
      (is (not (nil? (token :secret))))
      (is (not (nil? (token :verifier))))
      (is (= (token :callback_url "http://test.com/callback")))
      (is (= (token :scope "http://test.com/calendar")))
      (is (= (store/get-request-token :memory (token :token)) token))
      )
    )

  (deftest
    #^{:doc "Create but don't store an access token"}
    new-access-token
    (let [token (store/new-access-token)]
      (is (not (nil? (token :token))))
      (is (not (nil? (token :secret))))
      )
    )

  (deftest
    #^{:doc "Create and store an access token"}
    create-access-token
    (let [token (store/create-access-token :memory)]
      (is (not (nil? (token :token))))
      (is (not (nil? (token :secret))))
      (is (= (store/get-access-token :memory (token :token)) token))
      )
    )

  
  (deftest  
    #^{:doc "get access-token from memory"}
    get-access-token
    (is (= (store/get-access-token :memory nil) nil))
    (is (= (store/get-access-token :memory "") nil))
  )

  (deftest  
    #^{:doc "store access-token in memory"}
    store-access-token
    (let [access-token (store/store-access-token :memory {:token "access-token" :secret "ssh"}) ]
      (is (= access-token {:token "access-token" :secret "ssh"}))
      (is (= (store/get-access-token :memory "access-token") {:token "access-token" :secret "ssh"}))
      )
  )
  
  (deftest  
    #^{:doc "revoke access-token in memory"}
    revoke-access-token
    (let [access-token (store/store-access-token :memory {:token "access-token" :secret "ssh"}) ]
      (do
        (store/revoke-access-token :memory "access-token")
        (is (= (store/get-access-token :memory "access-token") nil))
        )
      )
  )
