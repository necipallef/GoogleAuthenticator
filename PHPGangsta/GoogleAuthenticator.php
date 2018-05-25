<?php

/**
 * PHP Class for handling Google Authenticator 2-factor authentication.
 *
 * @author Michael Kliewe
 * @copyright 2012 Michael Kliewe
 * @license http://www.opensource.org/licenses/bsd-license.php BSD License
 *
 * @link http://www.phpgangsta.de/
 */
class PHPGangsta_GoogleAuthenticator
{
    private $code_length = 6;

    /**
     * @param string $string
     * @return string
     */
    public function generateSecretFromString($string)
    {
        $lookup = $this->getBase32LookupTable();

        $secret = '';
        for ($i = 0; $i < strlen($string); $i++) {
            $char = $string[$i];
            $secret .= $lookup[ord($char) & 31];
        }

        return $secret;
    }

    /**
     * @param int $secretLength
     * @return string
     * @throws Exception
     */
    public function generateSecret($secretLength = 16)
    {
        // Valid secret lengths are 80 to 640 bits
        if ($secretLength < 16 || $secretLength > 128) {
            throw new Exception('Bad secret length');
        }

        $rnd = false;
        if (function_exists('random_bytes')) {
            $rnd = random_bytes($secretLength);
        } elseif (function_exists('mcrypt_create_iv')) {
            $rnd = mcrypt_create_iv($secretLength, MCRYPT_DEV_URANDOM);
        } elseif (function_exists('openssl_random_pseudo_bytes')) {
            $rnd = openssl_random_pseudo_bytes($secretLength, $cryptoStrong);
            if (!$cryptoStrong) {
                $rnd = false;
            }
        }

        if ($rnd === false) {
            throw new Exception('No source of secure random');
        }

        return $this->generateSecretFromString($rnd);
    }

    /**
     * @param string $secret
     * @param int|null $time_slice
     * @return string
     */
    public function getCode($secret, $time_slice = null)
    {
        if ($time_slice === null) {
            $time_slice = floor(time() / 30);
        }

        $secret_key = $this->base32Decode($secret);

        $time = chr(0) . chr(0) . chr(0) . chr(0) . pack('N*', $time_slice);
        $hash_mac = hash_hmac('SHA1', $time, $secret_key, true);
        $offset = ord(substr($hash_mac, -1)) & 0x0F;
        $hash_part = substr($hash_mac, $offset, 4);

        $value = unpack('N', $hash_part);
        $value = $value[1];
        $value = $value & 0x7FFFFFFF;
        $modulo = pow(10, $this->code_length);
        return str_pad($value % $modulo, $this->code_length, '0', STR_PAD_LEFT);
    }

    /**
     * @param string $secret
     * @param string $code
     * @param int $discrepancy
     * @return bool
     */
    public function verifyCode($secret, $code, $discrepancy = 1)
    {
        $current_time_slice = floor(time() / 30);
        if (strlen($code) != $this->code_length) {
            return false;
        }

        for ($i = -$discrepancy; $i <= $discrepancy; ++$i) {
            $calculatedCode = $this->getCode($secret, $current_time_slice + $i);
            if ($this->timingSafeEquals($calculatedCode, $code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param string $length
     * @return $this
     */
    public function setCodeLength($length)
    {
        $this->code_length = $length;
        return $this;
    }

    /**
     * @param string $secret
     * @return bool|string
     */
    private function base32Decode($secret)
    {
        if (empty($secret)) {
            return '';
        }

        $base32_chars = $this->getBase32LookupTable();
        $base32_chars_flipped = array_flip($base32_chars);

        $padding_char_count = substr_count($secret, $base32_chars[32]);
        $allowed_values = array(6, 4, 3, 1, 0);
        if (!in_array($padding_char_count, $allowed_values)) {
            return false;
        }
        for ($i = 0; $i < 4; ++$i) {
            if ($padding_char_count == $allowed_values[$i] &&
                substr($secret, -($allowed_values[$i])) != str_repeat($base32_chars[32], $allowed_values[$i])) {
                return false;
            }
        }
        $secret = str_replace('=', '', $secret);
        $secret = str_split($secret);
        $binary_string = '';
        for ($i = 0; $i < count($secret); $i = $i + 8) {
            $x = '';
            if (!in_array($secret[$i], $base32_chars)) {
                return false;
            }
            for ($j = 0; $j < 8; ++$j) {
                $x .= str_pad(base_convert(@$base32_chars_flipped[@$secret[$i + $j]], 10, 2), 5, '0', STR_PAD_LEFT);
            }
            $eight_bits = str_split($x, 8);
            for ($z = 0; $z < count($eight_bits); ++$z) {
                $binary_string .= (($y = chr(base_convert($eight_bits[$z], 2, 10))) || ord($y) == 48) ? $y : '';
            }
        }

        return $binary_string;
    }

    /**
     * @param string $safe_string
     * @param string $user_string
     * @return bool
     */
    private function timingSafeEquals($safe_string, $user_string)
    {
        if (function_exists('hash_equals')) {
            return hash_equals($safe_string, $user_string);
        }
        $safe_length = strlen($safe_string);
        $user_length = strlen($user_string);

        if ($user_length != $safe_length) {
            return false;
        }

        $result = 0;

        for ($i = 0; $i < $user_length; ++$i) {
            $result |= (ord($safe_string[$i]) ^ ord($user_string[$i]));
        }

        return $result === 0;
    }

    private function getBase32LookupTable()
    {
        return array(
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', //  7
            'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', // 15
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', // 23
            'Y', 'Z', '2', '3', '4', '5', '6', '7', // 31
            '=',  // padding char
        );
    }

}
