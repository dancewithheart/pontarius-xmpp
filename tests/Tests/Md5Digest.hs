{-# LANGUAGE OverloadedStrings #-}

module Tests.Md5Digest where

import qualified Data.ByteString as BS
import Test.Hspec
import Test.Tasty (TestTree)
import Test.Tasty.HUnit (testCase)
import Network.Xmpp.Sasl.Mechanisms.DigestMd5
  ( digestMd5Response
  , md5Hex
  , md5Raw
  )
import Tests.SaslCrypto (hex)

digestMd5 :: TestTree
digestMd5 =
  testCase "DigestMd5" $ hspec spec

spec :: Spec
spec = do
  describe "DIGEST-MD5 crypto helpers" $ do
    -- RFC 2831 Using Digest Authentication as a SASL Mechanism
    -- https://www.rfc-editor.org/rfc/rfc2831.html
    it "computes DIGEST-MD5 RFC 2831 response" $ do
      digestMd5Response
        "chris"
        (Just "elwood.innosoft.com")
        "secret"
        "imap/elwood.innosoft.com"
        "00000001"
        "auth"
        "OA6MG9tEQGm2hh"
        "OA6MHXh6VqTrRk"
        `shouldBe` "d388dad90d4bbd760a152321f2143af7"

    -- RFC 1321 MD5 Message-Digest Algorithm
    -- https://www.rfc-editor.org/rfc/rfc1321.txt
    it "computes MD5 RFC 1321 hex digest" $ do
      md5Hex ["abc"] `shouldBe` "900150983cd24fb0d6963f7d28e17f72"

    it "computes MD5 raw digest bytes" $ do
      hex (md5Raw ["abc"]) `shouldBe` "900150983cd24fb0d6963f7d28e17f72"

    it "keeps md5Raw as raw bytes, not hex text" $ do
      BS.length (md5Raw ["abc"]) `shouldBe` 16
