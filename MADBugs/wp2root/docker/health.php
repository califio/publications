<?php
header( 'Content-Type: application/json; charset=utf-8' );
echo json_encode(
	array(
		'php_version'       => PHP_VERSION,
		'php_sapi'          => PHP_SAPI,
		'disable_functions' => (string) ini_get( 'disable_functions' ),
	)
);
