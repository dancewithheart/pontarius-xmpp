{-# OPTIONS_HADDOCK hide #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.Xmpp.Sasl.Mechanisms.Scram
  where

import           Control.Applicative ((<$>))
import           Control.Monad
import           Control.Monad.Except
import           Control.Monad.State.Strict
import qualified Crypto.Hash             as Hash
import qualified Crypto.MAC.HMAC         as HMAC
import qualified Data.ByteArray          as BA
import qualified Data.ByteString         as BS
import qualified Data.ByteString.Base64  as B64
import           Data.ByteString.Char8   as BS8 (unpack)
import           Data.List (foldl1', genericTake)
import Data.Proxy (Proxy(..))
import qualified Data.Text               as Text
import qualified Data.Text.Encoding      as Text
import           Network.Xmpp.Sasl.Common
import           Network.Xmpp.Sasl.Types
import           Network.Xmpp.Types

-- | A nicer name for undefined, for use as a dummy token to determin
-- the hash function to use
hashToken :: Proxy hash
hashToken = Proxy

hashBytes
  :: forall hash proxy
   . Hash.HashAlgorithm hash
  => proxy hash
  -> BS.ByteString
  -> BS.ByteString
hashBytes _ =
  BA.convert . (Hash.hash :: BS.ByteString -> Hash.Digest hash)

hmacBytes
  :: forall hash proxy
   . Hash.HashAlgorithm hash
  => proxy hash
  -> BS.ByteString
  -> BS.ByteString
  -> BS.ByteString
hmacBytes _ key msg =
  BA.convert (HMAC.hmac key msg :: HMAC.HMAC hash)

-- | Salted Challenge Response Authentication Mechanism (SCRAM) SASL
-- mechanism according to RFC 5802.
--
-- This implementation is independent and polymorphic in the used hash function.
scram :: Hash.HashAlgorithm hash
      => Proxy hash      -- ^ Dummy argument to determine the hash to use; you
                         --   can safely pass undefined or a 'hashToken' to it
      -> Text.Text       -- ^ Authentication ID (user name)
      -> Maybe Text.Text -- ^ Authorization ID
      -> Text.Text       -- ^ Password
      -> ExceptT AuthFailure (StateT StreamState IO) ()
scram hToken authcid authzid password = do
    (ac, az, pw) <- prepCredentials authcid authzid password
    scramhelper ac az pw
  where
    scramhelper authcid' authzid' pwd = do
        cnonce <- liftIO makeNonce
        _ <- saslInit "SCRAM-SHA-1" (Just $ cFirstMessage cnonce)
        sFirstMessage <- saslFromJust =<< pullChallenge
        prs <- toPairs sFirstMessage
        (nonce, salt, ic) <- fromPairs prs cnonce
        let (cfm, v) = cFinalMessageAndVerifier nonce salt ic sFirstMessage cnonce
        _ <- respond $ Just cfm
        finalPairs <- toPairs =<< saslFromJust =<< pullFinalMessage
        unless (lookup "v" finalPairs == Just v) $ throwError AuthOtherFailure -- TODO: Log
        return ()
      where
        hash :: BS.ByteString -> BS.ByteString
        hash = hashBytes hToken

        hmac :: BS.ByteString -> BS.ByteString -> BS.ByteString
        hmac = hmacBytes hToken
        authzid'' :: Maybe BS.ByteString
        authzid''              = (\z -> "a=" +++ Text.encodeUtf8 z) <$> authzid'

        gs2CbindFlag :: BS.ByteString
        gs2CbindFlag         = "n" -- we don't support channel binding yet

        gs2Header :: BS.ByteString
        gs2Header            = merge $ [ gs2CbindFlag
                                       , maybe "" id authzid''
                                       , ""
                                       ]
        -- cbindData :: BS.ByteString
        -- cbindData            = "" -- we don't support channel binding yet

        cFirstMessageBare :: BS.ByteString -> BS.ByteString
        cFirstMessageBare cnonce = merge [ "n=" +++ Text.encodeUtf8 authcid'
                                         , "r=" +++ cnonce]
        cFirstMessage :: BS.ByteString -> BS.ByteString
        cFirstMessage cnonce = gs2Header +++ cFirstMessageBare cnonce

        fromPairs :: Pairs
                  -> BS.ByteString
                  -> ExceptT AuthFailure (StateT StreamState IO) (BS.ByteString, BS.ByteString, Integer)
        fromPairs prs cnonce | Just nonce <- lookup "r" prs
                             , cnonce `BS.isPrefixOf` nonce
                             , Just salt' <- lookup "s" prs
                             , Right salt <- B64.decode salt'
                             , Just ic <- lookup "i" prs
                             , [(i,"")] <- reads $ BS8.unpack ic
                             = return (nonce, salt, i)
        fromPairs _ _ = throwError $ AuthOtherFailure -- TODO: Log

        cFinalMessageAndVerifier :: BS.ByteString
                                 -> BS.ByteString
                                 -> Integer
                                 -> BS.ByteString
                                 -> BS.ByteString
                                 -> (BS.ByteString, BS.ByteString)
        cFinalMessageAndVerifier nonce salt ic sfm cnonce
            =  (merge [ cFinalMessageWOProof
                      , "p=" +++ B64.encode clientProof
                      ]
              , B64.encode serverSignature
              )
          where
            cFinalMessageWOProof :: BS.ByteString
            cFinalMessageWOProof = merge [ "c=" +++ B64.encode gs2Header
                                         , "r=" +++ nonce]

            saltedPassword :: BS.ByteString
            saltedPassword       = hi (Text.encodeUtf8 pwd) salt ic

            clientKey :: BS.ByteString
            clientKey            = hmac saltedPassword "Client Key"

            storedKey :: BS.ByteString
            storedKey            = hash clientKey

            authMessage :: BS.ByteString
            authMessage          = merge [ cFirstMessageBare cnonce
                                         , sfm
                                         , cFinalMessageWOProof
                                         ]

            clientSignature :: BS.ByteString
            clientSignature      = hmac storedKey authMessage

            clientProof :: BS.ByteString
            clientProof          = clientKey `xorBS` clientSignature

            serverKey :: BS.ByteString
            serverKey            = hmac saltedPassword "Server Key"

            serverSignature :: BS.ByteString
            serverSignature      = hmac serverKey authMessage

            -- helper
            hi :: BS.ByteString -> BS.ByteString -> Integer -> BS.ByteString
            hi str slt ic' = foldl1' xorBS (genericTake ic' us)
              where
                u1 = hmac str (slt +++ (BS.pack [0,0,0,1]))
                us = iterate (hmac str) u1

scramSha1 :: Username  -- ^ username
          -> Maybe AuthZID -- ^ authorization ID
          -> Password   -- ^ password
          -> SaslHandler
scramSha1 authcid authzid passwd =
    ( "SCRAM-SHA-1"
    , do
          r <- runExceptT $ scram (Proxy :: Proxy Hash.SHA1) authcid authzid passwd
          case r of
              Left (AuthStreamFailure e) -> return $ Left e
              Left e -> return $ Right $ Just e
              Right () -> return $ Right Nothing
    )
