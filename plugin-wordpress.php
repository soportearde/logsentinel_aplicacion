<?php
/**
 * Plugin Name: LogSentinel WP Logger
 * Description: Envía logs de acceso de WordPress al endpoint del LogCollector (LogSentinel).
 * Version:     1.0.0
 * Author:      LogSentinel
 */

// Seguridad: si alguien llama este archivo directamente, lo bloqueamos
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// ─────────────────────────────────────────────────────────────────
// CONFIGURACIÓN — Cambia la URL si tu LogCollector está en otro host
// ─────────────────────────────────────────────────────────────────
define( 'LOGSENTINEL_ENDPOINT', 'http://172.19.0.1:5000/log' );

// ─────────────────────────────────────────────────────────────────
// FUNCIÓN PRINCIPAL: Envía el log al LogCollector
// ─────────────────────────────────────────────────────────────────
function logsentinel_send( array $extra = [] ) {

    // Cogemos la IP real del visitante (teniendo en cuenta proxies)
    $source_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
        // Si hay proxy, cogemos la primera IP de la cadena
        $parts     = explode( ',', $_SERVER['HTTP_X_FORWARDED_FOR'] );
        $source_ip = trim( $parts[0] );
    }

    // Construimos el payload base que el LogCollector espera
    $payload = array_merge( [
        'source_system' => 'wordpress',           // El normalizer lo detectará como web_server
        'source_ip'     => $source_ip,
        'user_agent'    => substr( $_SERVER['HTTP_USER_AGENT'] ?? 'unknown', 0, 200 ),
        'method'        => $_SERVER['REQUEST_METHOD'] ?? 'GET',
        'path'          => $_SERVER['REQUEST_URI']    ?? '/',
        'username'      => is_user_logged_in()
                            ? wp_get_current_user()->user_login
                            : 'anonymous',
    ], $extra );  // Mezclamos con los campos extra que nos pasen (event_type, status, etc.)

    // Enviamos con wp_remote_post (la forma correcta en WordPress de hacer HTTP)
    wp_remote_post( LOGSENTINEL_ENDPOINT, [
        'headers'   => [ 'Content-Type' => 'application/json' ],
        'body'      => wp_json_encode( $payload ),
        'timeout'   => 3,
        'blocking'  => true,    // Necesario para que el envío no se pierda en acciones con redirección
    ] );
}


// ─────────────────────────────────────────────────────────────────
// HOOK 1: Login correcto
// ─────────────────────────────────────────────────────────────────
add_action( 'wp_login', function( $user_login, $user ) {
    logsentinel_send( [
        'event_type' => 'login',
        'status'     => 'success',
        'username'   => $user_login,
        'message'    => "Login correcto: {$user_login}",
    ] );
}, 10, 2 );


// ─────────────────────────────────────────────────────────────────
// HOOK 2: Login fallido
// ─────────────────────────────────────────────────────────────────
add_action( 'wp_login_failed', function( $username ) {
    logsentinel_send( [
        'event_type' => 'login_failed',
        'status'     => 'failure',
        'username'   => $username,
        'message'    => "Login fallido para usuario: {$username}",
    ] );
} );


// ─────────────────────────────────────────────────────────────────
// HOOK 3: Logout
// ─────────────────────────────────────────────────────────────────
add_action( 'wp_logout', function( $user_id ) {
    $user = get_userdata( $user_id );
    logsentinel_send( [
        'event_type' => 'logout',
        'status'     => 'success',
        'username'   => $user ? $user->user_login : 'unknown',
        'message'    => 'Sesión cerrada',
    ] );
} );


// ─────────────────────────────────────────────────────────────────
// HOOK 4: Acceso a cualquier página (tráfico web general)
// Usamos 'wp' que se ejecuta cuando WordPress ya sabe qué página mostrar
// ─────────────────────────────────────────────────────────────────
add_action( 'wp', function() {
    // Ignoramos las peticiones de assets (imágenes, CSS, JS, favicon...)
    $path = $_SERVER['REQUEST_URI'] ?? '/';
    $skip_extensions = [ '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.svg' ];
    foreach ( $skip_extensions as $ext ) {
        if ( str_ends_with( strtolower( $path ), $ext ) ) {
            return; // No enviamos log para recursos estáticos
        }
    }

    // Determinamos el status HTTP aproximado
    $status = is_404() ? 404 : 200;

    logsentinel_send( [
        'event_type' => 'page_access',
        'status'     => $status,
        'message'    => "Acceso a: {$path}",
    ] );
} );


// ─────────────────────────────────────────────────────────────────
// HOOK 5: Acceso al panel de administración (/wp-admin)
// ─────────────────────────────────────────────────────────────────
add_action( 'admin_init', function() {
    $path = $_SERVER['REQUEST_URI'] ?? '/wp-admin';

    logsentinel_send( [
        'event_type' => 'admin_access',
        'status'     => 200,
        'message'    => "Acceso al panel de administración: {$path}",
    ] );
} );


// ─────────────────────────────────────────────────────────────────
// HOOK 6: Intento de acceso a área restringida sin permisos
// Se dispara cuando current_user_can() devuelve false en wp-admin
// ─────────────────────────────────────────────────────────────────
add_action( 'admin_page_access_denied', function() {
    $path = $_SERVER['REQUEST_URI'] ?? '/wp-admin';

    logsentinel_send( [
        'event_type' => 'restricted_area_access',
        'status'     => 403,
        'path'       => $path,
        'message'    => "Acceso denegado a área restringida: {$path}",
    ] );
} );


// ─────────────────────────────────────────────────────────────────
// HOOK 7: Nuevo usuario administrador creado
// Usamos $userdata directamente (sin get_userdata) para evitar problemas de caché
// ─────────────────────────────────────────────────────────────────
add_action( 'user_register', function( $user_id, $userdata = [] ) {
    // $userdata contiene los datos originales del formulario (WP 5.8+)
    $role     = $userdata['role'] ?? '';
    $username = $userdata['user_login'] ?? "user_{$user_id}";
    $email    = $userdata['user_email'] ?? '';

    // Si no viene en $userdata (WP < 5.8), lo leemos de _POST como fallback
    if ( empty( $role ) ) {
        $role = sanitize_text_field( wp_unslash( $_POST['role'] ?? '' ) );
    }

    if ( $role !== 'administrator' ) {
        return;
    }

    logsentinel_send( [
        'event_type' => 'new_admin_created',
        'status'     => 200,
        'username'   => $username,
        'message'    => "Nuevo usuario administrador creado: {$username} ({$email})",
    ] );
}, 10, 2 );


// ─────────────────────────────────────────────────────────────────
// HOOK 8: Usuario existente promocionado a administrador
// Se dispara cuando se cambia el rol de un usuario ya existente
// ─────────────────────────────────────────────────────────────────
add_action( 'set_user_role', function( $user_id, $role, $old_roles ) {
    if ( $role !== 'administrator' ) {
        return;
    }

    $user = get_userdata( $user_id );
    logsentinel_send( [
        'event_type' => 'new_admin_created',
        'status'     => 200,
        'username'   => $user ? $user->user_login : "user_{$user_id}",
        'message'    => "Usuario promocionado a administrador: " . ( $user ? $user->user_login : $user_id ),
    ] );
}, 10, 3 );
