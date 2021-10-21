<?php
namespace egamov\encryption;

use egamov\encryption\Filter;

class StreamDecorator {
    protected $_inp_stream ;

    protected $_stream_filter ;

    protected $_encryption_key ;

    protected $_algorithm ;

    protected $_filtername ;

    const ALGORITHM_DEFAULT = 'aes-256-cbc' ;

    public function __construct( &$inp_stream , string $encryption_key = null , $algorithm = self::ALGORITHM_DEFAULT ) {
        $this->_inp_stream = static::to_stream( $inp_stream ) ;
        $this->_encryption_key = $encryption_key ;
        $this->_algorithm = $algorithm ;
        $this->_filtername = sha1( static::class ) ;
    }

    protected static function to_stream( &$inp ) {
        if ( is_resource( $inp ) ) {
            return $inp ;
        }

        $tmpfh = tmpfile( ) ;
        fwrite( $tmpfh , $inp ) ;
        fseek( $tmpfh , 0 , \SEEK_SET ) ;

        $inp = $tmpfh ;

        return $inp ;
    }

    public function encrypt( $out_stream = null ) {
        return $this->translate( 'encrypt' , $out_stream ) ;
    }

    public function decrypt( $out_stream = null ) {
        return $this->translate( 'decrypt' , $out_stream ) ;
    }

    protected function translate( string $action , $out_stream = null ) {
        $this->_stream_filter = stream_filter_register( $this->_filtername , Filter::class ) ;
        stream_filter_append( $this->_inp_stream , $this->_filtername , STREAM_FILTER_ALL , [
            'algorithm' => $this->_algorithm ,
            'encryption_key' => $this->_encryption_key ,
            'action' => $action ,
        ] ) ;

        if ( $out_stream ) {
            $this->copy_to( $out_stream ) ;
        }

        return $this->_inp_stream ;
    }

    protected function copy_to( $out ) {
        stream_copy_to_stream( $this->_inp_stream , $out ) ;

        // when output stream is seekable
        @fseek( $out , 0 , \SEEK_SET ) ;

        // when input stream is seekable
        @fseek( $this->_inp_stream , 0 , \SEEK_SET ) ;

        return $out ;
    }

    public function done( ) : boolean {
        return stream_filter_remove( $this->_stream_filter ) ;
    }

    public function encryption_key( string $encryption_key = null ) {
        if ( ! is_null( $encryption_key ) ) {
            $this->_encryption_key = $encryption_key ;

            return $this->_encryption_key ;
        }
        if ( is_null( $this->_encryption_key ) ) {
            $this->_encryption_key = Filter::get_encryption_key( ) ;
        }

        return $this->_encryption_key ;
    }
}