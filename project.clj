(defproject clj-oauth "1.4.1-SNAPSHOT"
  :description "OAuth support for Clojure"
  :repositories {"snapshots" {:url "s3p://lein-snapshots/snapshots"}}
  :dependencies [[org.clojure/clojure "1.4.0"]
                 [bouncycastle/bcprov-jdk16 "140"]
                 [commons-codec/commons-codec "1.8"]
                 [clj-http "0.5.3"]]
  :min-lein-version "2.0.0")
