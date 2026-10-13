<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Verifies that an enrolled key lives inside a genuine TPM 2.0 chip.
 *
 * The device proves it in three steps, all checked here with OpenSSL only:
 *  1. Its endorsement key (EK) certificate chains to a TPM manufacturer root we trust.
 *  2. Credential activation: we encrypt a random secret to that EK, bound to the name of a
 *     fresh attestation key (AK). Only a TPM that holds both the EK and the AK can recover it.
 *  3. That AK certifies (signs) the signing key's name over our enrolment nonce, and the
 *     certified attributes say the key is fixed to the chip and was generated inside it.
 *
 * What is proven: the key is non-exportable and lives in a TPM whose maker is the one named in
 * the certificate. What is not: revocation (CRLs are not checked) and the firmware's security.
 * Only ECC P-256 endorsement keys with SHA-256 names are supported.
 */
class Thessley_Passkey_Tpm {

	const ALG_ECC    = 0x0023;
	const ALG_SHA256 = 0x000B;
	const ALG_NULL   = 0x0010;
	const ALG_ECDSA  = 0x0018;
	const ALG_AES    = 0x0006;
	const CURVE_P256 = 0x0003;
	const MAGIC      = 0xFF544347;
	const ST_CERTIFY = 0x8017;

	const ATTR_FIXEDTPM            = 0x00000002;
	const ATTR_FIXEDPARENT         = 0x00000010;
	const ATTR_SENSITIVEDATAORIGIN = 0x00000020;
	const ATTR_RESTRICTED          = 0x00010000;
	const ATTR_DECRYPT             = 0x00020000;
	const ATTR_SIGN                = 0x00040000;

	/** SPKI header for an uncompressed prime256v1 public key. */
	const P256_SPKI_PREFIX = '3059301306072a8648ce3d020106082a8648ce3d030107034200';

	// --- small parsing helpers ------------------------------------------------------------

	/**
	 * Reads $len bytes at &$off, or throws.
	 *
	 * @param string $data Buffer.
	 * @param int    $off  Offset, advanced.
	 * @param int    $len  Bytes to read.
	 * @return string
	 * @throws InvalidArgumentException When the buffer is too short.
	 */
	protected static function take( $data, &$off, $len ) {
		if ( $len < 0 || $off + $len > strlen( $data ) ) {
			throw new InvalidArgumentException( 'Truncated TPM structure.' );
		}
		$out  = substr( $data, $off, $len );
		$off += $len;
		return $out;
	}

	protected static function u16( $data, &$off ) {
		$v = unpack( 'n', self::take( $data, $off, 2 ) );
		return $v[1];
	}

	protected static function u32( $data, &$off ) {
		$v = unpack( 'N', self::take( $data, $off, 4 ) );
		return $v[1];
	}

	protected static function tpm2b( $data, &$off ) {
		return self::take( $data, $off, self::u16( $data, $off ) );
	}

	protected static function pad32( $bin ) {
		$bin = ltrim( $bin, "\0" );
		if ( strlen( $bin ) > 32 ) {
			throw new InvalidArgumentException( 'Value too long for P-256.' );
		}
		return str_pad( $bin, 32, "\0", STR_PAD_LEFT );
	}

	// --- TPMT_PUBLIC ----------------------------------------------------------------------------

	/**
	 * Parses an ECC TPMT_PUBLIC (not the TPM2B wrapper).
	 *
	 * @param string $raw Marshalled TPMT_PUBLIC.
	 * @return array type, nameAlg, attributes, authPolicy, scheme, curve, x, y.
	 * @throws InvalidArgumentException When it is not a supported public area.
	 */
	public static function parse_public( $raw ) {
		$off         = 0;
		$type        = self::u16( $raw, $off );
		$name_alg    = self::u16( $raw, $off );
		$attributes  = self::u32( $raw, $off );
		$auth_policy = self::tpm2b( $raw, $off );
		if ( self::ALG_ECC !== $type || self::ALG_SHA256 !== $name_alg ) {
			throw new InvalidArgumentException( 'Only ECC keys named with SHA-256 are supported.' );
		}
		$sym = self::u16( $raw, $off );
		if ( self::ALG_NULL !== $sym ) {
			if ( self::ALG_AES !== $sym ) {
				throw new InvalidArgumentException( 'Unsupported symmetric algorithm.' );
			}
			self::u16( $raw, $off );
			self::u16( $raw, $off );
		}
		$scheme = self::u16( $raw, $off );
		if ( self::ALG_NULL !== $scheme ) {
			self::u16( $raw, $off );
		}
		$curve = self::u16( $raw, $off );
		$kdf   = self::u16( $raw, $off );
		if ( self::ALG_NULL !== $kdf ) {
			self::u16( $raw, $off );
		}
		$x = self::tpm2b( $raw, $off );
		$y = self::tpm2b( $raw, $off );
		if ( strlen( $raw ) !== $off ) {
			throw new InvalidArgumentException( 'Trailing bytes after the public area.' );
		}
		if ( self::CURVE_P256 !== $curve ) {
			throw new InvalidArgumentException( 'Only the P-256 curve is supported.' );
		}
		return array(
			'type'       => $type,
			'nameAlg'    => $name_alg,
			'attributes' => $attributes,
			'authPolicy' => $auth_policy,
			'scheme'     => $scheme,
			'curve'      => $curve,
			'x'          => self::pad32( $x ),
			'y'          => self::pad32( $y ),
		);
	}

	/** TPM object name: nameAlg || H(TPMT_PUBLIC). */
	public static function name( $tpmt_public ) {
		return pack( 'n', self::ALG_SHA256 ) . hash( 'sha256', $tpmt_public, true );
	}

	/** PEM public key from a P-256 point. */
	public static function point_to_pem( $x, $y ) {
		$der = hex2bin( self::P256_SPKI_PREFIX ) . "\x04" . self::pad32( $x ) . self::pad32( $y );
		return "-----BEGIN PUBLIC KEY-----\n" . chunk_split( base64_encode( $der ), 64, "\n" ) . "-----END PUBLIC KEY-----\n"; // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- DER to PEM, not obfuscation.
	}

	/** The (x, y) of an SPKI DER P-256 key, or null if it is not one. */
	public static function spki_to_point( $spki_der ) {
		$prefix = hex2bin( self::P256_SPKI_PREFIX );
		if ( strlen( $prefix ) + 65 !== strlen( $spki_der ) || 0 !== strncmp( $spki_der, $prefix, strlen( $prefix ) ) || "\x04" !== $spki_der[ strlen( $prefix ) ] ) {
			return null;
		}
		$point = substr( $spki_der, strlen( $prefix ) + 1 );
		return array(
			'x' => substr( $point, 0, 32 ),
			'y' => substr( $point, 32, 32 ),
		);
	}

	// --- 1. EK certificate chain -----------------------------------------------------------------

	/**
	 * Checks the EK certificate chain against the trusted roots.
	 *
	 * @param string[]        $der_certs  Leaf (the EK certificate) first, then any intermediates, as DER.
	 * @param string[]|string $root_files PEM file(s) holding trusted TPM manufacturer roots.
	 * @return array|null The EK's P-256 point (x, y) and the maker named in the certificate; null if it does not verify.
	 */
	public static function verify_ek_chain( array $der_certs, $root_files ) {
		$root_files = array_values( array_filter( (array) $root_files, 'is_file' ) );
		if ( ! $der_certs || count( $der_certs ) > 8 || ! $root_files ) {
			return null;
		}
		$pems = array();
		foreach ( $der_certs as $der ) {
			if ( ! is_string( $der ) || '' === $der || strlen( $der ) > 8192 ) {
				return null;
			}
			$pems[] = "-----BEGIN CERTIFICATE-----\n" . chunk_split( base64_encode( $der ), 64, "\n" ) . "-----END CERTIFICATE-----\n"; // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- DER to PEM, not obfuscation.
		}

		$untrusted = null;
		try {
			if ( count( $pems ) > 1 ) {
				if ( ! function_exists( 'wp_tempnam' ) ) {
					require_once ABSPATH . 'wp-admin/includes/file.php'; // not loaded for REST/front-end requests.
				}
				$untrusted = wp_tempnam( 'tpmchain' );
				file_put_contents( $untrusted, implode( '', array_slice( $pems, 1 ) ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- short-lived temp file in the system temp dir for OpenSSL.
				$ok = @openssl_x509_checkpurpose( $pems[0], X509_PURPOSE_ANY, $root_files, $untrusted ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- OpenSSL warns on malformed input; the result is checked.
			} else {
				$ok = @openssl_x509_checkpurpose( $pems[0], X509_PURPOSE_ANY, $root_files ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- as above.
			}
		} finally {
			if ( null !== $untrusted ) {
				wp_delete_file( $untrusted );
			}
		}
		if ( true !== $ok ) {
			return null;
		}

		$key     = @openssl_pkey_get_public( $pems[0] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- malformed input is handled below.
		$details = $key ? openssl_pkey_get_details( $key ) : false;
		if ( ! $details || OPENSSL_KEYTYPE_EC !== ( $details['type'] ?? null ) || 'prime256v1' !== ( $details['ec']['curve_name'] ?? '' ) ) {
			return null;
		}

		$parsed = openssl_x509_parse( $pems[0] );
		$san    = (string) ( $parsed['extensions']['subjectAltName'] ?? '' );
		$eku    = (string) ( $parsed['extensions']['extendedKeyUsage'] ?? '' );
		if ( '' !== $eku && false === strpos( $eku, '2.23.133.8.1' ) && false === stripos( $eku, 'tcg-kp-EKCertificate' ) && false === stripos( $eku, 'Endorsement Key Certificate' ) ) {
			return null;
		}
		$maker = '';
		$model = '';
		if ( preg_match( '/(?:2\.23\.133\.2\.1|tpmManufacturer)\s*=\s*id:([0-9A-Fa-f]{8})/', $san, $m ) ) {
			$maker = trim( hex2bin( $m[1] ), "\0 " );
		}
		if ( preg_match( '/(?:2\.23\.133\.2\.2|tpmModel)\s*=\s*([^\/,]+)/', $san, $m ) ) {
			$model = substr( trim( $m[1] ), 0, 32 );
		}
		return array(
			'x'            => self::pad32( $details['ec']['x'] ),
			'y'            => self::pad32( $details['ec']['y'] ),
			'manufacturer' => $maker,
			'model'        => $model,
		);
	}

	// --- 2. credential activation -------------------------------------------------------------------

	/** TPM2 KDFa (SP 800-108 counter mode, HMAC-SHA256). */
	protected static function kdfa( $key, $label, $context_u, $context_v, $bits ) {
		$out     = '';
		$counter = 1;
		while ( strlen( $out ) * 8 < $bits ) {
			$out .= hash_hmac( 'sha256', pack( 'N', $counter ) . $label . "\0" . $context_u . $context_v . pack( 'N', $bits ), $key, true );
			++$counter;
		}
		return substr( $out, 0, intdiv( $bits, 8 ) );
	}

	/**
	 * TPM2_MakeCredential for an ECC P-256 EK: encrypts $secret so only the TPM holding the EK and
	 * a loaded object named $ak_name can recover it.
	 *
	 * @param string $ek_x    EK point x.
	 * @param string $ek_y    EK point y.
	 * @param string $ak_name Name of the attestation key.
	 * @param string $secret  1-32 bytes.
	 * @return array credential_blob and secret: marshalled TPM2B_ID_OBJECT and TPM2B_ENCRYPTED_SECRET.
	 * @throws InvalidArgumentException|RuntimeException On bad input or a crypto failure.
	 */
	public static function make_credential( $ek_x, $ek_y, $ak_name, $secret ) {
		if ( strlen( $secret ) < 1 || strlen( $secret ) > 32 ) {
			throw new InvalidArgumentException( 'Credential must be 1-32 bytes.' );
		}
		$eph = openssl_pkey_new(
			array(
				'curve_name'       => 'prime256v1',
				'private_key_type' => OPENSSL_KEYTYPE_EC,
			)
		);
		if ( ! $eph ) {
			throw new RuntimeException( 'Could not create an ephemeral key.' );
		}
		$details = openssl_pkey_get_details( $eph );
		$qe_x    = self::pad32( $details['ec']['x'] );
		$qe_y    = self::pad32( $details['ec']['y'] );
		$peer    = openssl_pkey_get_public( self::point_to_pem( $ek_x, $ek_y ) );
		$z       = $peer ? openssl_pkey_derive( $peer, $eph, 32 ) : false;
		if ( false === $z ) {
			throw new RuntimeException( 'ECDH failed.' );
		}
		$z = self::pad32( $z );

		// Seed: concatenation KDF (SP 800-56A) over SHA-256, one block.
		$seed     = hash( 'sha256', pack( 'N', 1 ) . $z . "IDENTITY\0" . $qe_x . self::pad32( $ek_x ), true );
		$sym_key  = self::kdfa( $seed, 'STORAGE', $ak_name, '', 128 );
		$enc      = openssl_encrypt( pack( 'n', strlen( $secret ) ) . $secret, 'aes-128-cfb', $sym_key, OPENSSL_RAW_DATA, str_repeat( "\0", 16 ) );
		$hmac_key = self::kdfa( $seed, 'INTEGRITY', '', '', 256 );
		$outer    = hash_hmac( 'sha256', $enc . $ak_name, $hmac_key, true );
		$id_obj   = pack( 'n', strlen( $outer ) ) . $outer . $enc;

		return array(
			'credential_blob' => pack( 'n', strlen( $id_obj ) ) . $id_obj,
			'secret'          => pack( 'n', 2 + 32 + 2 + 32 ) . pack( 'n', 32 ) . $qe_x . pack( 'n', 32 ) . $qe_y,
		);
	}

	// --- 3. certification of the signing key ----------------------------------------------------------

	/** Raw (r, s) to a DER ECDSA signature. */
	protected static function ecdsa_der( $r, $s ) {
		$int  = static function ( $v ) {
			$v = ltrim( $v, "\0" );
			if ( '' === $v || ord( $v[0] ) > 0x7F ) {
				$v = "\0" . $v;
			}
			return "\x02" . chr( strlen( $v ) ) . $v;
		};
		$body = $int( $r ) . $int( $s );
		return "\x30" . chr( strlen( $body ) ) . $body;
	}

	/**
	 * Verifies the AK's certification of the signing key.
	 *
	 * @param string $ak_public      TPMT_PUBLIC of the attestation key.
	 * @param string $attest         TPMS_ATTEST bytes the AK signed.
	 * @param string $signature      Marshalled TPMT_SIGNATURE (ECDSA / SHA-256).
	 * @param string $key_public     TPMT_PUBLIC of the signing key that was certified.
	 * @param string $nonce          What the AK had to sign in as qualifying data (the enrolment nonce).
	 * @param string $submitted_spki The public key the site is being asked to store (SPKI DER).
	 * @return string|null Null when everything checks out, otherwise a short reason.
	 */
	public static function verify_certification( $ak_public, $attest, $signature, $key_public, $nonce, $submitted_spki ) {
		try {
			$ak  = self::parse_public( $ak_public );
			$key = self::parse_public( $key_public );
		} catch ( InvalidArgumentException $e ) {
			return 'unparseable public area';
		}

		// The AK must be a restricted signing key fixed to the chip: otherwise it could be made to sign anything.
		$ak_need = self::ATTR_FIXEDTPM | self::ATTR_FIXEDPARENT | self::ATTR_RESTRICTED | self::ATTR_SIGN;
		if ( ( $ak['attributes'] & $ak_need ) !== $ak_need || ( $ak['attributes'] & self::ATTR_DECRYPT ) ) {
			return 'attestation key is not a restricted, fixed signing key';
		}
		// The certified key: generated inside and tied to this TPM, and a plain signing key.
		$key_need = self::ATTR_FIXEDTPM | self::ATTR_FIXEDPARENT | self::ATTR_SENSITIVEDATAORIGIN | self::ATTR_SIGN;
		if ( ( $key['attributes'] & $key_need ) !== $key_need || ( $key['attributes'] & ( self::ATTR_RESTRICTED | self::ATTR_DECRYPT ) ) ) {
			return 'signing key is not fixed to the TPM';
		}
		$point = self::spki_to_point( $submitted_spki );
		if ( null === $point || ! hash_equals( $point['x'], $key['x'] ) || ! hash_equals( $point['y'], $key['y'] ) ) {
			return 'certified key is not the submitted key';
		}

		// The signature, by the AK.
		$off = 0;
		try {
			$alg  = self::u16( $signature, $off );
			$hash = self::u16( $signature, $off );
			$r    = self::tpm2b( $signature, $off );
			$s    = self::tpm2b( $signature, $off );
		} catch ( InvalidArgumentException $e ) {
			return 'unparseable signature';
		}
		if ( self::ALG_ECDSA !== $alg || self::ALG_SHA256 !== $hash || strlen( $signature ) !== $off ) {
			return 'unexpected signature algorithm';
		}
		$ak_key = openssl_pkey_get_public( self::point_to_pem( $ak['x'], $ak['y'] ) );
		if ( ! $ak_key || 1 !== openssl_verify( $attest, self::ecdsa_der( $r, $s ), $ak_key, OPENSSL_ALGO_SHA256 ) ) {
			return 'bad certification signature';
		}

		// What was signed.
		try {
			$off = 0;
			$magic = self::u32( $attest, $off );
			$type  = self::u16( $attest, $off );
			self::tpm2b( $attest, $off );
			$extra = self::tpm2b( $attest, $off );
			self::take( $attest, $off, 8 + 4 + 4 + 1 + 8 );
			$certified = self::tpm2b( $attest, $off );
			self::tpm2b( $attest, $off );
			if ( strlen( $attest ) !== $off ) {
				return 'trailing bytes in the attestation';
			}
		} catch ( InvalidArgumentException $e ) {
			return 'unparseable attestation';
		}
		if ( self::MAGIC !== $magic || self::ST_CERTIFY !== $type ) {
			return 'not a TPM certification';
		}
		if ( ! hash_equals( $nonce, $extra ) ) {
			return 'certification is not bound to this enrolment';
		}
		if ( ! hash_equals( self::name( $key_public ), $certified ) ) {
			return 'certified name does not match the key';
		}
		return null;
	}
}
