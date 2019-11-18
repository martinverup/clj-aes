(ns clj-aes.aes-128
  (:require [clj-aes.shared :refer :all]))

(defonce block-size 16)

(defonce r [0x01 0x02 0x04 0x08 0x10 0x20 0x40 0x80 0x1b 0x36])

(defonce indecies [13 14 15 12 0 1 2 3 4 5 6 7 8 9 10 11])

(defn- sub-bytes [in]
  (map #(get s-box %) in))

(defn- shift-rows [in]
  (let [shift [0 1 2 3
               5 6 7 4
               10 11 8 9
               15 12 13 14]]
    (map #(nth in %) shift)))

(defn- xtime [v]
  (let [out (bit-shift-left v 1)]
    (if (= (bit-shift-right v 7) 1)
      (bit-xor out 0x1b)
      out)))

(defn- mix-columns [a]
  (flatten (for [j [0 4 8 12]]
             (let [t (bit-xor (nth a j) (nth a (+ j 1)) (nth a (+ j 2)) (nth a (+ j 3)))]
               (for [k (range 4)]
                 (let [i (+ j k)
                       this (nth a i)
                       next (nth a (mod (inc i) 4))
                       v (xtime (bit-xor this next))]
                   (bit-xor this v t)))))))

(defn- add-round-key [key in]
  (xor-collections in key))

(defn- key-schedule [round key]
  (map-indexed (fn [index byte] (let [k (nth indecies index)
                                      l (->> k (nth key) (nth s-box))]
                                  (bit-xor byte (if (> k 11)
                                                  (if (= index 0)
                                                    (bit-xor l (nth r round))
                                                    l)
                                                  (nth key k))))) key))

(defn- encrypt-block [key in]
  (let [byte-key (first (string->byte-blocks-with-padding block-size key))]
    (loop [round 0
           c (add-round-key byte-key in)
           k (key-schedule round in)]
      (if (< 10 round)
        (recur (inc round)
               (->> c
                    sub-bytes
                    shift-rows
                    mix-columns
                    (add-round-key k))
               (key-schedule (inc round) k))
        (->> c
             sub-bytes
             shift-rows
             (add-round-key k))))))

(defn ecb-encrypt [key pt]
  (let [result (->> pt
                    (string->byte-blocks-with-padding block-size)
                    (map #(encrypt-block key %)))]
    {:encrypted-bytes  result
     :encrypted-string (byte-blocks->string result)}))

(defn cbc-encrypt
  ([key first-iv pt]
   (loop [iv first-iv
          blocks (string->byte-blocks-with-padding block-size pt)
          result []]
     (if (empty? blocks)
       {:iv               first-iv
        :encrypted-bytes  result
        :encrypted-string (byte-blocks->string result)}
       (let [encrypted-block (->> blocks
                                  first
                                  (xor-collections iv)
                                  (encrypt-block key))]
         (recur encrypted-block (rest blocks) (concat result encrypted-block))))))
  ([key pt]
   (cbc-encrypt key (vec (gen-iv block-size)) pt)))

(defn cfb-encrypt
  ([key first-iv pt]
   (loop [iv first-iv
          blocks (string->byte-blocks-with-padding block-size pt)
          result []]
     (if (empty? blocks)
       {:iv               first-iv
        :encrypted-bytes  result
        :encrypted-string (byte-blocks->string result)}
       (let [encrypted-block (->> iv
                                  (encrypt-block key)
                                  (xor-collections (first blocks)))]
         (recur encrypted-block (rest blocks) (concat result encrypted-block))))))
  ([key pt]
   (cfb-encrypt key (vec (gen-iv block-size)) pt)))

(defn cfb-decrypt [key first-iv ct]
  (loop [iv first-iv
         blocks (partition-all block-size ct)
         result []]
    (if (empty? blocks)
      (byte-blocks->string-without-padding result)
      (let [decrypted-block (->> iv
                                 (encrypt-block key)
                                 (xor-collections (first blocks)))]
        (recur (first blocks) (rest blocks) (concat result decrypted-block))))))
