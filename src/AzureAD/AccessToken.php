<?php

namespace AzureAD\AccessToken

use Namshi\JOSE\SimpleJWS;

class AccessToken
{
    public function parseAccessToken($token)
    {
        $keyId       = $this->getKeyId($token);
        $content     = $this->getCertificateContent($keyId);
        $certificate = $this->getCertificate($content);
        $publicKey   = $this->getPublicKey($certificate);
        $jws         = $this->validateToken($token, $publicKey);
        return $jws ? $jws->getPayload() : false;
    }

    // helpers

    private function getKeyId($jwt)
    {
        $header = $this->getJwtHeader($jwt);
        $header = base64_decode($header);
        $header = json_decode($header, true);
        return $header['kid'];
    }

    /**
     * Get a certificate that matches a key id
     *
     * @param String $keyId
     *
     * @return String|Boolean Certificate on success
     */
    private function getCertificateContent($keyId)
    {
        /*
         *  Get the keys where the format is:
         *
         *  {
         *    "keys": [
         *      {
         *        "x5c": [
         *          "MII.."
         *        ],
         *        "e": "AQAB",
         *        "n": "7eI..",
         *        "x5t": "_UgqXG_tMLduSJ1T8caHxU7cOtc",
         *        "kid": "_UgqXG_tMLduSJ1T8caHxU7cOtc",
         *        "use": "sig",
         *        "kty": "RSA"
         *      },
         *      ..
         *  }
         *
         * @todo: these keys need to be cached
         */
        $keys = file_get_contents('https://login.windows.net/common/discovery/keys');

        $json = json_decode($keys, true);
        $keys = $json['keys'];
        foreach ($keys as $key) {
            if ($key['kid'] === $keyId) {
                return $key['x5c'][0];
            }
        }

        return false;
    }

    /**
     * @see hwi/HWIOAuthBundle/OAuth/ResourceOwner/.*
     */
    private function getJwtHeader($jwt)
    {
        list($header,,) = explode('.', $jwt, 3);

        // if the token was urlencoded, ensure that it is valid base64 encoded
        $header = str_replace(array('-', '_'), array('+', '/'), $header);

        // padding
        switch (strlen($header) % 4) {
            case 0:
                break;
            case 2:
                $header .= '=';
            case 3:
                $header .= '=';
                break;
            default:
                throw new \InvalidArgumentException('Invalid base64 format sent back');
        }

        return $header;
    }

    private function getCertificate($certificate)
    {
        // @see: http://stackoverflow.com/a/32185275/1589512
        return "-----BEGIN CERTIFICATE-----\n"
            . chunk_split($certificate, 64)
            . "-----END CERTIFICATE-----\n";
    }

    /**
     * Get the public key from the certificate
     *
     * @param  string $certificate
     * @return resource Public Key
     */
    private function getPublicKey($certificate)
    {
        $certificate = openssl_x509_read($certificate);
        $publicKey = openssl_pkey_get_public($certificate);
        return $publicKey;
    }

    /**
     * @param string   $token     Access Token from Azure AD (JWT)
     * @param resource $publicKey
     * @return Namshi\JOSE\SimpleJWS|false
     */
    private function validateToken($token, $publicKey)
    {
        $jws = SimpleJWS::load($token);
        if (!$jws->isValid($publicKey)) {
            return false;
        }
        return $jws;
    }
}
