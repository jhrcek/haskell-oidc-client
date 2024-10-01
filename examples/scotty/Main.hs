{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

module Main where

import           Control.Monad.IO.Class               (liftIO)
import           Control.Monad.Reader                 (ReaderT, ask, lift,
                                                       runReaderT)
import           Crypto.Random                        (SystemDRG, getSystemDRG,
                                                       randomBytesGenerate)
import           Data.Aeson                           (FromJSON)
import           Data.ByteString                      (ByteString)
import           Data.ByteString.Base64.URL           (encode)
import qualified Data.ByteString.Char8                as B
import           Data.IORef                           (IORef,
                                                       atomicModifyIORef',
                                                       newIORef, readIORef)
import           Data.List                            as L
import           Data.Map                             (Map)
import qualified Data.Map                             as M
import           Data.Maybe                           (fromMaybe)
import           Data.Text                            as T
import           Data.Text.Encoding                   (decodeUtf8)
import           Data.Text.Lazy                       as TL
import           Data.Tuple                           (swap)
import           GHC.Generics                         (Generic)
import           Network.HTTP.Client                  (newManager)
import           Network.HTTP.Client.TLS              (tlsManagerSettings)
import           Network.HTTP.Types                   (badRequest400,
                                                       unauthorized401)
import           Network.Wai.Middleware.RequestLogger (logStdoutDev)
import           System.Environment                   (getEnv)
import           Text.Blaze.Html                      (Html)
import           Text.Blaze.Html.Renderer.Text        (renderHtml)
import qualified Text.Blaze.Html5                     as H
import           Text.Blaze.Html5                     ((!))
import qualified Text.Blaze.Html5.Attributes          as A
import qualified Web.OIDC.Client                      as O
import qualified Web.OIDC.Client.IdTokenFlow          as IdTokenFlow
import           Web.Scotty.Cookie                    (getCookie,
                                                       setSimpleCookie)
import           Web.Scotty.Trans                     (ScottyT, formParam,
                                                       formParamMaybe, get,
                                                       html, middleware, post,
                                                       redirect, scottyT,
                                                       status, text)

type SessionStateMap = Map T.Text (O.State, O.Nonce)

data AuthServerEnv = AuthServerEnv
    { oidc :: O.OIDC
    , sdrg :: IORef SystemDRG
    , ssm  :: IORef SessionStateMap
    }

type AuthServer a = ScottyT (ReaderT AuthServerEnv IO) a

data ProfileClaims = ProfileClaims
    { name  :: T.Text
    , email :: T.Text
    , oid   :: T.Text -- https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference#use-claims-to-reliably-identify-a-user
    } deriving (Show, Generic)

instance FromJSON ProfileClaims

main :: IO ()
main = do
    baseUrl      <- B.pack <$> getEnv "OPENID_CLIENT_BASE_URL"
    clientId     <- B.pack <$> getEnv "OPENID_CLIENT_ID"
    clientSecret <- B.pack <$> getEnv "OPENID_CLIENT_SECRET"

    let port = getPort baseUrl
        redirectUri = baseUrl <> "/login/cb"

    sdrg <- getSystemDRG >>= newIORef
    ssm  <- newIORef M.empty
    mgr  <- newManager tlsManagerSettings
    prov <- O.discover "https://login.microsoftonline.com/51c57df9-9362-47d4-a307-e5e76dcb3b15/v2.0" mgr
    let oidc = O.setCredentials clientId clientSecret redirectUri $ O.newOIDC prov

    run port oidc sdrg ssm

getPort :: ByteString -> Int
getPort bs = fromMaybe 3000 port
  where
    port = case B.split ':' bs of
        []  -> Nothing
        [_] -> Nothing
        xs  -> let p = (!! 0) . L.reverse $ xs
                    in fst <$> B.readInt p

run :: Int -> O.OIDC -> IORef SystemDRG -> IORef SessionStateMap ->  IO ()
run port oidc sdrg ssm = scottyT port runReader run'
  where
    runReader a = runReaderT a (AuthServerEnv oidc sdrg ssm)

run' :: AuthServer ()
run' = do
    middleware logStdoutDev

    get "/login" $
        blaze htmlLogin

    post "/login" $ do
        AuthServerEnv{..} <- lift ask

        sid <- genSessionId sdrg
        let store = sessionStoreFromSession sdrg ssm sid
        loc <- liftIO $ IdTokenFlow.prepareAuthenticationRequestUrl store oidc [O.email, O.profile] []
        setSimpleCookie cookieName sid
        redirect . TL.pack $ show loc

    post "/login/cb" $ do
        err <- formParamMaybe "error"
        case err of
            Just e  -> status401 e
            Nothing -> getCookie cookieName >>= doCallback

  where
    cookieName = "test-session"

    htmlLogin = do
        H.h1 "Login"
        H.form ! A.method "post" ! A.action "/login" $
            H.button ! A.type_ "submit" $ "login"

    doCallback cookie =
        case cookie of
            Just sid -> do
                AuthServerEnv{..} <- lift ask
                let store = sessionStoreFromSession sdrg ssm sid
                state <- formParam "state"
                idToken  <- formParam "id_token"
                tokens <- liftIO $ IdTokenFlow.getValidIdTokenClaims store oidc state (pure idToken)
                blaze $ htmlResult tokens
            Nothing  -> status400 "cookie not found"

    htmlResult :: O.IdTokenClaims ProfileClaims -> Html
    htmlResult tokenClaims = do
        H.h1 "Result"
        H.p . H.toHtml $ show tokenClaims
        let profile = O.otherClaims tokenClaims
        H.div $ do
            H.p $ do
                H.toHtml ("Name: " :: T.Text)
                H.toHtml (name profile)
            H.p $ do
                H.toHtml ("Email: " :: T.Text)
                H.toHtml (email profile)
            H.p $ do
                H.toHtml ("OID: " :: T.Text)
                H.toHtml (oid profile)

    gen sdrg                   = encode <$> atomicModifyIORef' sdrg (swap . randomBytesGenerate 64)
    genSessionId sdrg          = liftIO $ decodeUtf8 <$> gen sdrg
    genBytes sdrg              = liftIO $ gen sdrg
    saveState ssm sid st nonce = liftIO $ atomicModifyIORef' ssm $ \m -> (M.insert sid (st, nonce) m, ())
    getStateBy ssm sid _st     = liftIO $ do
        m <- M.lookup sid <$> readIORef ssm
        return $ case m of
            Just (_, nonce) -> Just nonce
            _               -> Nothing
    deleteState ssm sid  = liftIO $ atomicModifyIORef' ssm $ \m -> (M.delete sid m, ())

    sessionStoreFromSession sdrg ssm sid =
        O.SessionStore
            { sessionStoreGenerate = genBytes sdrg
            , sessionStoreSave     = saveState ssm sid
            , sessionStoreGet      = getStateBy ssm sid
            , sessionStoreDelete   = const $ deleteState ssm sid
            }

    blaze = html . renderHtml
    status400 m = status badRequest400   >> text m
    status401 m = status unauthorized401 >> text m
