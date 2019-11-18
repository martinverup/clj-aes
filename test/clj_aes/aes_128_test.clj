(ns clj-aes.aes-128_test
  (:require [clojure.test :refer :all]
            [clj-aes.aes-128 :refer :all]))

(deftest test-cbc-enryption
  (testing "CBC encryption"
    (is (= 0 1))))
