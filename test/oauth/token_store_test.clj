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