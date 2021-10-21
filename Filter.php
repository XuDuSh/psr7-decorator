<?php
namespace egamov\encryption ;

class Filter extends \PHP_User_Filter {

    public $filtername ;

    protected $_data ;

    protected $iv ;

    protected $cipher_iv_len ;

    protected $encryption_key ;

    protected $method ;

    protected $algorithm ;

    protected $is_encrypt ;

    protected $is_decrypt ;

    public static function methods_available( ) {
        return openssl_get_cipher_methods( ) ;
    }

    public function onCreate( ) {
        $this->method = null ;
        $this->filtername = sha1( static::class ) ;

        if ( ! isset( $this->params[ 'encryption_key' ] ) || ! mb_strlen( $this->params[ 'encryption_key' ] ) ) {
            throw new \Exception( 'Param "encryption_key" is empty' ) ;
        }
        if ( ! in_array( @$this->params[ 'algorithm' ] , static::methods_available( ) ) ) {
            throw new \Exception( 'Algorithm "' . $this->params[ 'algorithm' ] . '" not supported' ) ;
        }

        switch ( @$this->params[ 'action' ] ) {
            case 'encrypt' : {
                $this->method = 'openssl_encrypt' ;
                $this->is_encrypt = true ;

                break ;
            }
            case 'decrypt' : {
                $this->method = 'openssl_decrypt' ;
                $this->is_decrypt = true ;

                break ;
            }
            default : {
                throw new \Exception( 'Param "action" isn\'t either "encrypt" or "decrypt"' ) ;
            }
        }

        $this->algorithm = $this->params[ 'algorithm' ] ;
        $this->encryption_key = $this->params[ 'encryption_key' ] ;
        $this->iv = $this->get_iv( ) ;
        $this->cipher_iv_len = strlen( $this->iv ) ;
        $this->_data = '' ;

        return true ;
    }

    protected function get_iv( ) {
        $cipher_iv_len = openssl_cipher_iv_length( $this->algorithm ) ;

        return openssl_random_pseudo_bytes( $cipher_iv_len ) ;
    }

     public static function get_encryption_key( ) {
        return sha1( uniqid( ) ) ;
    }

    public function filter( $inp , $out , &$consumed , $closing ) {
        /* We read all the stream data and store it in
           the '$_data' variable
        */
        if ( $bucket = stream_bucket_make_writeable( $inp ) ) {
            $this->_data .= str_repeat( ' ' , $this->cipher_iv_len ) . $bucket->data ;
            $this->bucket = $bucket ;
        }
        while ( $bucket = stream_bucket_make_writeable( $inp ) ) {
            $this->_data .= $bucket->data ;
            $this->bucket = $bucket ;
        }
        if ( empty( $closing ) || empty( $this->bucket ) ) {
            return \PSFS_FEED_ME ;
        }

        $consumed += mb_strlen( $this->_data ) ;

        // enryption\decryption
        $this->bucket->data = ( $this->method )( $this->_data , $this->algorithm , $this->encryption_key , 0 , $this->iv ) ;

        if ( $this->is_decrypt ) {
            $this->bucket->data = substr( $this->bucket->data , $this->cipher_iv_len ) ;
        }

        $this->bucket->datalen = mb_strlen( $this->_data ) ;

        if( empty( $this->bucket->data ) ) {
            return \PSFS_PASS_ON ;
        }

        stream_bucket_append( $out , $this->bucket ) ;

        return \PSFS_PASS_ON ;
    }
}