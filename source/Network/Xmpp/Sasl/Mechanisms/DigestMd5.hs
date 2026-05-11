{-# OPTIONS_HADDOCK hide #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.Xmpp.Sasl.Mechanisms.DigestMd5
    ( digestMd5
    ) where

import           Control.Monad.Except
import           Control.Monad.State.Strict
import qualified Crypto.Hash            as Hash
import qualified Data.ByteArray         as BA
import qualified Data.ByteString        as BS
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as BS8
import qualified Data.List as L
import           Data.Text (Text)
import qualified Data.Text.Encoding as Text
import           Network.Xmpp.Sasl.Common
import           Network.Xmpp.Sasl.Types
import           Network.Xmpp.Types



xmppDigestMd5 ::  Text -- ^ Authentication identity (authzid or username)
               -> Maybe Text -- ^ Authorization identity (authcid)
               -> Text -- ^ Password (authzid)
               -> ExceptT AuthFailure (StateT StreamState IO) ()
xmppDigestMd5 authcid' authzid' password' = do
    (ac, az, pw) <- prepCredentials authcid' authzid' password'
    Just address <- gets streamAddress
    xmppDigestMd5' address ac az pw
  where
    xmppDigestMd5' :: Text -> Text -> Maybe Text -> Text -> ExceptT AuthFailure (StateT StreamState IO) ()
    xmppDigestMd5' hostname authcid _authzid password = do -- TODO: use authzid?
        -- Push element and receive the challenge.
        _ <- saslInit "DIGEST-MD5" Nothing -- TODO: Check boolean?
        prs <- toPairs =<< saslFromJust =<< pullChallenge
        cnonce <- liftIO $ makeNonce
        _b <- respond . Just $ createResponse hostname prs cnonce
        _challenge2 <- pullFinalMessage
        return ()
      where
        -- Produce the response to the challenge.
        createResponse :: Text
                       -> Pairs
                       -> BS.ByteString -- nonce
                       -> BS.ByteString
        createResponse hname prs cnonce = let
            Just qop   = L.lookup "qop" prs -- TODO: proper handling
            Just nonce = L.lookup "nonce" prs
            uname_     = Text.encodeUtf8 authcid
            passwd_    = Text.encodeUtf8 password
            -- Using Int instead of Word8 for random 1.0.0.0 (GHC 7)
            -- compatibility.

            nc         = "00000001"
            digestURI  = "xmpp/" `BS.append` Text.encodeUtf8 hname
            digest     = md5Digest
                uname_
                (lookup "realm" prs)
                passwd_
                digestURI
                nc
                qop
                nonce
                cnonce
            response = BS.intercalate "," . map (BS.intercalate "=") $
                [["username", quote uname_]] ++
                    case L.lookup "realm" prs of
                        Just realm -> [["realm" , quote realm ]]
                        Nothing -> [] ++
                            [ ["nonce"     , quote nonce    ]
                            , ["cnonce"    , quote cnonce   ]
                            , ["nc"        ,       nc       ]
                            , ["qop"       ,       qop      ]
                            , ["digest-uri", quote digestURI]
                            , ["response"  ,       digest   ]
                            , ["charset"   ,       "utf-8"  ]
                            ]
            in B64.encode response
        -- lowercase hex MD5, used in DIGEST-MD5 response
        hash :: [BS.ByteString] -> BS.ByteString
        hash = BS8.pack . show
            . (Hash.hash :: BS.ByteString -> Hash.Digest Hash.MD5)
            . BS.intercalate ":"
        -- raw 16-byte MD5 digest, used for HA1 inner hash
        hashRaw :: [BS.ByteString] -> BS.ByteString
        hashRaw = BA.convert
            . (Hash.hash :: BS.ByteString -> Hash.Digest Hash.MD5)
            . BS.intercalate ":"
        -- TODO: this only handles MD5-sess
        md5Digest :: BS8.ByteString
                  -> Maybe BS8.ByteString
                  -> BS8.ByteString
                  -> BS8.ByteString
                  -> BS8.ByteString
                  -> BS8.ByteString
                  -> BS8.ByteString
                  -> BS8.ByteString
                  -> BS8.ByteString
        md5Digest uname realm pwd digestURI nc qop nonce cnonce =
          let ha1 = hash [ hashRaw [uname, maybe "" id realm, pwd]
                         , nonce
                         , cnonce
                         ]
              ha2 = hash ["AUTHENTICATE", digestURI]
          in hash [ha1, nonce, nc, cnonce, qop, ha2]

digestMd5 :: Username -- ^ Authentication identity (authcid or username)
          -> Maybe AuthZID -- ^ Authorization identity (authzid)
          -> Password -- ^ Password
          -> SaslHandler
digestMd5 authcid authzid password =
    ( "DIGEST-MD5"
    , do
          r <- runExceptT $ xmppDigestMd5 authcid authzid password
          case r of
              Left (AuthStreamFailure e) -> return $ Left e
              Left e -> return $ Right $ Just e
              Right () -> return $ Right Nothing
    )
