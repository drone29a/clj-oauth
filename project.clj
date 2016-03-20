(defproject clj-oauth "1.5.6-SNAPSHOT"
  :url "https://github.com/mattrepl/clj-oauth"
  :license {:name "Simplified BSD License"
            :url "https://opensource.org/licenses/BSD-2-Clause"
            :distribution :repo}
  :description "OAuth support for Clojure"
  :dependencies [[org.clojure/clojure "1.7.0"]
                 [commons-codec/commons-codec "1.8"]
                 [org.bouncycastle/bcprov-jdk15on "1.54"]
                 [org.bouncycastle/bcpkix-jdk15on "1.54"]
                 [clj-http "2.0.1"]])
