module Main where

import Test.Tasty

import Tests.Parsers
import Tests.Picklers
import Tests.Stream
import Tests.SaslCrypto
import Tests.Md5Digest

main :: IO ()
main = defaultMain $ testGroup "root" [ parserTests
                                      , picklerTests
                                      , streamTests
                                      , saslCrypto
                                      , digestMd5
                                      ]
