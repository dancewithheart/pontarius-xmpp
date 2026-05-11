{-# LANGUAGE OverloadedStrings #-}

module Tests.SaslCrypto
  ( saslCrypto
  , hex
  ) where

import qualified Crypto.Hash as Hash
import qualified Data.ByteString as BS
import Data.Proxy (Proxy(..))
import Data.Word (Word8)
import Numeric (showHex)
import Test.Hspec
import Test.Tasty (TestTree)
import Test.Tasty.HUnit (testCase)

import Network.Xmpp.Sasl.Mechanisms.Scram
  ( hashBytes
  , hmacBytes
  )

saslCrypto :: TestTree
saslCrypto =
  testCase "SaslCrypto" $ hspec spec

spec :: Spec
spec = do
  -- RFC 2202 Test Cases for HMAC-MD5 and HMAC-SHA-1
  -- https://www.rfc-editor.org/rfc/rfc2202.html
  describe "SCRAM crypto helpers" $ do
    it "computes SHA1 digest" $ do
      hex (hashBytes (Proxy :: Proxy Hash.SHA1) "abc")
        `shouldBe` "a9993e364706816aba3e25717850c26c9cd0d89d"

    it "computes HMAC-SHA1" $ do
      hex (hmacBytes (Proxy :: Proxy Hash.SHA1) "Jefe" "what do ya want for nothing?")
        `shouldBe` "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"

hex :: BS.ByteString -> String
hex = concatMap byteHex . BS.unpack

byteHex :: Word8 -> String
byteHex w =
  if length str == 1 then '0' : str else str
  where
    str = showHex w ""
