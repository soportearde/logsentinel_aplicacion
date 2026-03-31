<?php
/**
 * Plugin Name: LogSentinel WP Logger
 * Description: Envía logs de acceso de WordPress al LogCollector de LogSentinel.
 * Version:     2.0.0
 * Author:      LogSentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// ─────────────────────────────────────────────────────────────────
// CONFIGURACIÓN — URL del collector leída desde la BD de WordPress
// El admin la configura en Ajustes → LogSentinel
// ─────────────────────────────────────────────────────────────────
function logsentinel_collector_url(): string {
    $url = get_option( 'logsentinel_collector_url', '' );
    return rtrim( $url, '/' ) . '/log';
}


// ─────────────────────────────────────────────────────────────────
// FUNCIÓN PRINCIPAL: Envía el log al Collector
// ─────────────────────────────────────────────────────────────────
function logsentinel_send( array $extra = [] ): void {
    $collector_url = logsentinel_collector_url();

    // Si no está configurada la URL, no hacer nada
    if ( $collector_url === '/log' ) {
        return;
    }

    $source_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
        $parts     = explode( ',', $_SERVER['HTTP_X_FORWARDED_FOR'] );
        $source_ip = trim( $parts[0] );
    }

    $payload = array_merge( [
        'source_system' => 'wordpress',
        'source_ip'     => $source_ip,
        'user_agent'    => substr( $_SERVER['HTTP_USER_AGENT'] ?? 'unknown', 0, 200 ),
        'method'        => $_SERVER['REQUEST_METHOD'] ?? 'GET',
        'path'          => $_SERVER['REQUEST_URI']    ?? '/',
        'username'      => is_user_logged_in()
                            ? wp_get_current_user()->user_login
                            : 'anonymous',
    ], $extra );

    wp_remote_post( $collector_url, [
        'headers'   => [ 'Content-Type' => 'application/json' ],
        'body'      => wp_json_encode( $payload ),
        'timeout'   => 3,
        'blocking'  => false,  // No esperamos respuesta para no ralentizar WP
    ] );
}


// ─────────────────────────────────────────────────────────────────
// HOOKS DE EVENTOS
// ─────────────────────────────────────────────────────────────────
add_action( 'wp_login', function( $user_login, $user ) {
    logsentinel_send( [
        'event_type' => 'login_success',
        'username'   => $user_login,
        'message'    => "Login correcto: {$user_login}",
    ] );
}, 10, 2 );

add_action( 'wp_login_failed', function( $username ) {
    logsentinel_send( [
        'event_type' => 'login_failed',
        'username'   => $username,
        'message'    => "Login fallido para usuario: {$username}",
    ] );
} );

add_action( 'wp_logout', function( $user_id ) {
    $user = get_userdata( $user_id );
    logsentinel_send( [
        'event_type' => 'logout',
        'username'   => $user ? $user->user_login : 'unknown',
        'message'    => 'Sesión cerrada',
    ] );
} );


add_action( 'admin_page_access_denied', function() {
    $path = $_SERVER['REQUEST_URI'] ?? '/wp-admin';
    logsentinel_send( [
        'event_type' => 'restricted_area_access',
        'path'       => $path,
        'message'    => "Acceso denegado a área restringida: {$path}",
    ] );
} );

 //── Registro de nuevo usuario administrador ──────────────────────
add_action( 'user_register', function( $user_id, $userdata = [] ) {
    $role     = $userdata['role'] ?? '';
    $username = $userdata['user_login'] ?? "user_{$user_id}";
    $email    = $userdata['user_email'] ?? '';

    if ( empty( $role ) ) {
        $role = sanitize_text_field( wp_unslash( $_POST['role'] ?? '' ) );
    }
    if ( $role !== 'administrator' ) {
        return;
    }

    // Marcamos que este usuario acaba de ser registrado como admin
    // para que set_user_role no duplique el log
    global $logsentinel_just_registered;
    $logsentinel_just_registered = $user_id;

    logsentinel_send( [
        'event_type' => 'new_admin_created',       // Se mantiene: es un admin nuevo
        'username'   => $username,
        'message'    => "Nuevo administrador creado: {$username} ({$email})",
    ] );
}, 10, 2 );

// ── Cambio de rol a administrador (promoción) ───────────────────
add_action( 'set_user_role', function( $user_id, $role, $old_roles ) {
    if ( $role !== 'administrator' ) {
        return;
    }

    // Si este usuario acaba de ser registrado, el log ya se envió arriba
    global $logsentinel_just_registered;
    if ( isset( $logsentinel_just_registered ) && $logsentinel_just_registered === $user_id ) {
        // Limpiamos la marca y salimos sin enviar nada
        $logsentinel_just_registered = null;
        return;
    }

    // Si llegamos aquí, es un usuario existente al que le cambian el rol
    $user = get_userdata( $user_id );
    logsentinel_send( [
        'event_type' => 'admin_role_assigned',      // Distinto: es una promoción
        'username'   => $user ? $user->user_login : "user_{$user_id}",
        'message'    => "Usuario promocionado a administrador: " . ( $user ? $user->user_login : $user_id ),
    ] );
}, 10, 3 );


// ─────────────────────────────────────────────────────────────────
// PÁGINA DE AJUSTES EN WP-ADMIN → Ajustes → LogSentinel
// ─────────────────────────────────────────────────────────────────
add_action( 'admin_menu', function() {
    add_options_page(
        'LogSentinel',
        'LogSentinel',
        'manage_options',
        'logsentinel',
        'logsentinel_settings_page'
    );
} );

add_action( 'admin_init', function() {
    register_setting( 'logsentinel_settings', 'logsentinel_collector_url', [
        'sanitize_callback' => 'esc_url_raw',
    ] );
} );

function logsentinel_settings_page(): void {
    $url         = get_option( 'logsentinel_collector_url', '' );
    $test_result = '';

    // Botón de prueba
    if ( isset( $_POST['logsentinel_test'] ) && check_admin_referer( 'logsentinel_test_nonce' ) ) {
        $collector_url = rtrim( esc_url_raw( $_POST['logsentinel_collector_url'] ?? $url ), '/' ) . '/log';
        $response = wp_remote_post( $collector_url, [
            'headers' => [ 'Content-Type' => 'application/json' ],
            'body'    => wp_json_encode( [
                'source_system' => 'wordpress',
                'event_type'    => 'login_failed',
                'username'      => 'test_user',
                'source_ip'     => '1.2.3.4',
                'message'       => 'Evento de prueba desde LogSentinel WP Logger',
            ] ),
            'timeout'  => 5,
            'blocking' => true,
        ] );

        if ( is_wp_error( $response ) ) {
            $test_result = '<div class="notice notice-error"><p>Error: ' . esc_html( $response->get_error_message() ) . '</p></div>';
        } else {
            $code = wp_remote_retrieve_response_code( $response );
            $test_result = '<div class="notice notice-success"><p>Conexión correcta. El collector respondió con código <strong>' . esc_html( $code ) . '</strong>. Comprueba que se ha generado una alerta en LogSentinel.</p></div>';
        }
    }
    ?>
    <div class="wrap">
        <h1>LogSentinel — Configuración</h1>
        <?php echo $test_result; ?>
        <form method="post" action="options.php">
            <?php settings_fields( 'logsentinel_settings' ); ?>
            <table class="form-table">
                <tr>
                    <th scope="row"><label for="logsentinel_collector_url">URL del servidor LogSentinel</label></th>
                    <td>
                        <input type="url" id="logsentinel_collector_url" name="logsentinel_collector_url"
                               value="<?php echo esc_attr( $url ); ?>"
                               placeholder="http://20.238.17.71:5000"
                               class="regular-text" />
                        <p class="description">Introduce la URL base del servidor, por ejemplo: <code>http://20.238.17.71:5000</code></p>
                    </td>
                </tr>
            </table>
            <?php submit_button( 'Guardar' ); ?>
        </form>

        <hr>
        <h2>Probar conexión</h2>
        <p>Envía un evento de prueba <code>login_failed</code> al collector para verificar que todo funciona.</p>
        <form method="post">
            <?php wp_nonce_field( 'logsentinel_test_nonce' ); ?>
            <input type="hidden" name="logsentinel_collector_url" value="<?php echo esc_attr( $url ); ?>">
            <input type="submit" name="logsentinel_test" class="button button-secondary" value="Enviar evento de prueba">
        </form>
    </div>
    <?php
}
