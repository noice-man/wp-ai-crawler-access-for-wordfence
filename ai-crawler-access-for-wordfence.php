<?php
/**
 * Plugin Name: AI Crawler Access for Wordfence
 * Plugin URI: https://ворд-пресс.рф/plugins/ai-crawler-access-for-wordfence/
 * Update URI: https://xn----ctbgf6biedka.xn--p1ai/plugins/ai-crawler-access-for-wordfence/
 * Description: Безопасная диагностика доступа AI-краулеров, настройка виртуального robots.txt и проверка IP по официальным спискам без отключения Wordfence.
 * Version: 1.2.1
 * Author: Valery Molodtsov
 * Author URI: https://ворд-пресс.рф
 * License: GPL-2.0-or-later
 * Text Domain: ai-crawler-access-for-wordfence
 * Requires PHP: 7.4
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

require_once __DIR__ . '/includes/live-traffic.php';

/** Only published robots tokens for search and user-initiated access; NOT training crawlers. */
function waca_agents() {
    return array(
        'OAI-SearchBot'    => array( 'company' => 'OpenAI',     'purpose' => 'Поиск ChatGPT' ),
        'ChatGPT-User'     => array( 'company' => 'OpenAI',     'purpose' => 'Переход по запросу пользователя' ),
        'PerplexityBot'    => array( 'company' => 'Perplexity', 'purpose' => 'Поиск Perplexity' ),
        'Perplexity-User'  => array( 'company' => 'Perplexity', 'purpose' => 'Переход по запросу пользователя' ),
        'Claude-SearchBot' => array( 'company' => 'Anthropic',  'purpose' => 'Поиск Claude' ),
        'Claude-User'      => array( 'company' => 'Anthropic',  'purpose' => 'Переход по запросу пользователя' ),
    );
}

/** Published CIDR feeds; never used as Wordfence allowlists. */
function waca_feeds() {
    return array(
        'openai_search' => array( 'label' => 'OpenAI — OAI-SearchBot', 'url' => 'https://openai.com/searchbot.json' ),
        'openai_user'   => array( 'label' => 'OpenAI — ChatGPT-User', 'url' => 'https://openai.com/chatgpt-user.json' ),
        'openai_gptbot' => array( 'label' => 'OpenAI — GPTBot (обучение)', 'url' => 'https://openai.com/gptbot.json' ),
        'googlebot'     => array( 'label' => 'Google — обычные краулеры', 'url' => 'https://developers.google.com/crawling/ipranges/common-crawlers.json' ),
        'perplexity'    => array( 'label' => 'PerplexityBot', 'url' => 'https://www.perplexity.ai/perplexitybot.json' ),
        'perplexity_user'=>array( 'label' => 'Perplexity-User', 'url' => 'https://www.perplexity.ai/perplexity-user.json' ),
        'anthropic'     => array( 'label' => 'Anthropic — Claude', 'url' => 'https://claude.com/crawling/bots.json' ),
    );
}

function waca_active_wordfence() {
    if ( defined( 'WORDFENCE_VERSION' ) || class_exists( 'wordfence', false ) ) {
        return true;
    }
    $plugins = (array) get_option( 'active_plugins', array() );
    if ( in_array( 'wordfence/wordfence.php', $plugins, true ) ) {
        return true;
    }
    if ( is_multisite() ) {
        $network = (array) get_site_option( 'active_sitewide_plugins', array() );
        return isset( $network['wordfence/wordfence.php'] );
    }
    return false;
}

function waca_physical_robots_path() {
    if ( ! function_exists( 'get_home_path' ) ) {
        require_once ABSPATH . 'wp-admin/includes/file.php';
    }
    return trailingslashit( get_home_path() ) . 'robots.txt';
}

function waca_has_physical_robots() {
    $path = waca_physical_robots_path();
    return file_exists( $path ) || is_link( $path );
}

/**
 * Parse groups of robots.txt, including multiple adjacent User-agent lines.
 * Only used for conservative guards; not a full robots.txt RFC 9309 parser.
 */
function waca_robots_groups( $robots ) {
    $groups = array();
    $agents = array();
    $rules  = array();
    $had_rule = false;
    foreach ( preg_split( '/\r\n|\r|\n/', (string) $robots ) as $line ) {
        $line = trim( preg_replace( '/\s*#.*$/', '', $line ) );
        if ( '' === $line ) {
            continue;
        }
        if ( ! preg_match( '/^([a-z-]+)\s*:\s*(.*?)\s*$/i', $line, $m ) ) {
            continue;
        }
        $key = strtolower( $m[1] );
        $val = trim( $m[2] );
        if ( 'user-agent' === $key ) {
            if ( $had_rule ) {
                $groups[] = array( 'agents' => $agents, 'rules' => $rules );
                $agents = array();
                $rules = array();
                $had_rule = false;
            }
            if ( '' !== $val ) {
                $agents[] = strtolower( $val );
            }
        } elseif ( ! empty( $agents ) && in_array( $key, array( 'allow', 'disallow' ), true ) ) {
            $rules[] = array( 'kind' => $key, 'path' => $val );
            $had_rule = true;
        }
    }
    if ( ! empty( $agents ) ) {
        $groups[] = array( 'agents' => $agents, 'rules' => $rules );
    }
    return $groups;
}

/** Refuse to add groups if wildcard restrictions could be bypassed. */
function waca_is_safe_for_overlay( $robots ) {
    foreach ( waca_robots_groups( $robots ) as $group ) {
        if ( ! in_array( '*', $group['agents'], true ) ) {
            continue;
        }
        foreach ( $group['rules'] as $rule ) {
            if ( 'disallow' !== $rule['kind'] || '' === $rule['path'] ) {
                continue;
            }
            if ( ! in_array( $rule['path'], array( '/wp-admin/', '/wp-login.php' ), true ) ) {
                return false;
            }
        }
    }
    return true;
}

/** Respect explicit policy groups for bots, including shorter matching agent prefixes. */
function waca_existing_agent_policy( $groups, $token ) {
    foreach ( $groups as $group ) {
        foreach ( $group['agents'] as $agent ) {
            if ( '*' !== $agent && 0 === stripos( $token, $agent ) ) {
                return true;
            }
        }
    }
    return false;
}

/** Pure append generator for WordPress's virtual robots.txt; no file writes. */
function waca_overlay_text( $existing, $selected ) {
    if ( ! waca_is_safe_for_overlay( $existing ) ) {
        return $existing;
    }
    $groups = waca_robots_groups( $existing );
    $added = '';
    foreach ( array_keys( waca_agents() ) as $agent ) {
        if ( ! in_array( $agent, $selected, true ) || waca_existing_agent_policy( $groups, $agent ) ) {
            continue;
        }
        $added .= "\nUser-agent: " . $agent . "\nAllow: /\nDisallow: /wp-admin/\nDisallow: /wp-login.php\nAllow: /wp-admin/admin-ajax.php\n";
    }
    return $added ? rtrim( $existing ) . "\n\n# AI Crawler Access for Wordfence — administrator-approved rules\n" . ltrim( $added, "\n" ) : $existing;
}

/** Hook only the built-in WordPress virtual robots.txt endpoint. */
add_filter( 'robots_txt', 'waca_apply_virtual_robots', 9999, 2 );
function waca_apply_virtual_robots( $output, $public ) {
    if ( ! $public || (int) get_option( 'blog_public', 1 ) !== 1 || waca_has_physical_robots() ) {
        return $output;
    }
    $selected = get_option( 'waca_selected_agents', array() );
    if ( ! is_array( $selected ) || empty( $selected ) ) {
        return $output;
    }
    return waca_overlay_text( (string) $output, $selected );
}

/** True only when a site-wide virtual robots overlay can be delivered safely. */
function waca_overlay_possible( $existing = '' ) {
    if ( (int) get_option( 'blog_public', 1 ) !== 1 ) {
        return 'В настройках WordPress включено «Попросить поисковые системы не индексировать сайт». Автоматическое разрешение отключено.';
    }
    if ( waca_has_physical_robots() ) {
        return 'Обнаружен физический robots.txt: Nginx/Apache могут выдавать его напрямую. Плагин не меняет этот файл. Правила необходимо добавить вручную.';
    }
    if ( ! waca_is_safe_for_overlay( $existing ) ) {
        return 'В robots.txt есть дополнительные ограничения в общей группе User-agent: *. Чтобы их не обходить, автоматическое добавление правил запрещено. Настройте нужные группы вручную.';
    }
    return '';
}

/** Cached official prefix files: never allow traffic or change Wordfence options based on result. */
function waca_get_prefixes( $feed_id ) {
    $feeds = waca_feeds();
    if ( ! isset( $feeds[ $feed_id ] ) ) {
        return new WP_Error( 'unknown_feed', 'Неизвестный источник IP-адресов.' );
    }
    $cache_key = 'waca_feed_' . $feed_id;
    $cached = get_transient( $cache_key );
    if ( is_array( $cached ) && ! empty( $cached['prefixes'] ) ) {
        return $cached;
    }
    $res = wp_safe_remote_get( $feeds[ $feed_id ]['url'], array(
        'timeout' => 8,
        'redirection' => 2,
        'limit_response_size' => 350000,
        'headers' => array( 'Accept' => 'application/json' ),
    ) );
    if ( is_wp_error( $res ) ) {
        return new WP_Error( 'feed_network', 'Не удалось получить список IP: ' . $res->get_error_message() );
    }
    if ( 200 !== (int) wp_remote_retrieve_response_code( $res ) ) {
        return new WP_Error( 'feed_http', 'Источник списка IP ответил HTTP ' . (int) wp_remote_retrieve_response_code( $res ) . '.' );
    }
    $data = json_decode( wp_remote_retrieve_body( $res ), true );
    if ( ! is_array( $data ) || ! isset( $data['prefixes'] ) || ! is_array( $data['prefixes'] ) ) {
        return new WP_Error( 'feed_schema', 'Неизвестный формат списка IP. Проверка не выполнена.' );
    }
    $prefixes = array();
    foreach ( array_slice( $data['prefixes'], 0, 5000 ) as $row ) {
        if ( ! is_array( $row ) ) {
            continue;
        }
        foreach ( array( 'ipv4Prefix', 'ipv6Prefix' ) as $key ) {
            if ( ! empty( $row[ $key ] ) && is_string( $row[ $key ] ) && waca_valid_cidr( $row[ $key ] ) ) {
                $prefixes[] = $row[ $key ];
            }
        }
    }
    if ( ! $prefixes ) {
        return new WP_Error( 'feed_empty', 'В ответе нет корректных IP-диапазонов. Проверка не выполнена.' );
    }
    $value = array( 'prefixes' => array_values( array_unique( $prefixes ) ), 'fetched_at' => time() );
    set_transient( $cache_key, $value, 12 * HOUR_IN_SECONDS );
    return $value;
}

function waca_valid_cidr( $cidr ) {
    if ( ! is_string( $cidr ) || ! preg_match( '~^([^/]+)/([0-9]{1,3})$~', $cidr, $m ) ) {
        return false;
    }
    $bin = @inet_pton( $m[1] );
    return false !== $bin && (int) $m[2] <= strlen( $bin ) * 8;
}

/** Binary CIDR matching handles IPv4 and IPv6 without integer overflows. */
function waca_ip_in_cidr( $ip, $cidr ) {
    if ( ! waca_valid_cidr( $cidr ) ) {
        return false;
    }
    list( $network, $bits ) = explode( '/', $cidr, 2 );
    $addr = @inet_pton( $ip );
    $net  = @inet_pton( $network );
    if ( false === $addr || false === $net || strlen( $addr ) !== strlen( $net ) ) {
        return false;
    }
    $bits = (int) $bits;
    $full = intdiv( $bits, 8 );
    if ( substr( $addr, 0, $full ) !== substr( $net, 0, $full ) ) {
        return false;
    }
    $remaining = $bits % 8;
    if ( 0 === $remaining ) {
        return true;
    }
    $mask = ( 0xff << ( 8 - $remaining ) ) & 0xff;
    return ( ord( $addr[ $full ] ) & $mask ) === ( ord( $net[ $full ] ) & $mask );
}

/** Admin-triggered loopback tests do NOT prove real crawlers can pass Wordfence. */
function waca_test_url( $url, $method = 'HEAD' ) {
    $args = array( 'timeout' => 7, 'redirection' => 0, 'limit_response_size' => 100000 );
    $result = 'GET' === $method ? wp_safe_remote_get( $url, $args ) : wp_safe_remote_head( $url, $args );
    if ( is_wp_error( $result ) ) {
        return array( 'code' => 0, 'detail' => $result->get_error_message(), 'body' => '' );
    }
    return array(
        'code' => (int) wp_remote_retrieve_response_code( $result ),
        'detail' => (string) wp_remote_retrieve_header( $result, 'content-type' ),
        'body' => 'GET' === $method ? (string) wp_remote_retrieve_body( $result ) : '',
    );
}

function waca_scan_site() {
    $robots = waca_test_url( home_url( '/robots.txt' ), 'GET' );
    $scan = array(
        'time' => time(),
        'home' => waca_test_url( home_url( '/' ) ),
        'robots' => array( 'code' => $robots['code'], 'detail' => $robots['detail'] ),
        'llms' => waca_test_url( home_url( '/llms.txt' ) ),
        'robots_text' => 200 === $robots['code'] && strlen( $robots['body'] ) <= 100000 ? $robots['body'] : '',
    );
    update_option( 'waca_last_scan', $scan, false );
    return $scan;
}

function waca_notice( $message, $type = 'info' ) {
    $class = 'success' === $type ? 'notice-success' : ( 'error' === $type ? 'notice-error' : 'notice-warning' );
    echo '<div class="notice ' . esc_attr( $class ) . ' inline"><p>' . esc_html( $message ) . '</p></div>';
}

add_action( 'admin_menu', 'waca_admin_menu' );
function waca_admin_menu() {
    add_menu_page( 'AI Crawlers — Wordfence', 'AI Crawlers', 'manage_options', 'waca-admin', 'waca_admin_page', 'dashicons-visibility', 82 );
}

function waca_admin_page() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( 'Недостаточно прав.' );
    }
    $alert = '';
    $alert_type = 'info';
    $ip_check = null;

    if ( 'POST' === ( isset( $_SERVER['REQUEST_METHOD'] ) ? $_SERVER['REQUEST_METHOD'] : '' ) && isset( $_POST['waca_action'] ) ) {
        check_admin_referer( 'waca_admin_action', 'waca_nonce' );
        $action = sanitize_key( wp_unslash( $_POST['waca_action'] ) );
        if ( 'diagnose' === $action ) {
            waca_scan_site();
            $alert = 'Запросы к главной странице, robots.txt и llms.txt выполнены. Это тест с IP вашего хостинга, не с IP AI-краулера.';
            $alert_type = 'success';
        } elseif ( 'update_rules' === $action ) {
            $selected_raw = isset( $_POST['waca_agents'] ) && is_array( $_POST['waca_agents'] ) ? wp_unslash( $_POST['waca_agents'] ) : array();
            $selected = array_values( array_intersect( array_keys( waca_agents() ), array_map( 'sanitize_text_field', $selected_raw ) ) );
            $scan = get_option( 'waca_last_scan', array() );
            // Fail closed if diagnostics are not fresh. Need to know the actual served robots.txt.
            if ( $selected && ( ! is_array( $scan ) || empty( $scan['time'] ) || time() - $scan['time'] > 15 * MINUTE_IN_SECONDS || empty( $scan['robots_text'] ) || empty( $scan['robots']['code'] ) || 200 !== (int) $scan['robots']['code'] ) ) {
                $alert = 'Сначала нажмите «Проверить сайт». Нужен актуальный публичный robots.txt (HTTP 200), прежде чем включать правила.';
                $alert_type = 'error';
            } else {
                $guard = waca_overlay_possible( $selected ? $scan['robots_text'] : '' );
                if ( $selected && $guard ) {
                    $alert = $guard;
                    $alert_type = 'error';
                } else {
                    update_option( 'waca_selected_agents', $selected, false );
                    $alert = $selected ? 'Настройки сохранены. Правила добавляются только в виртуальный robots.txt WordPress. Проверьте публичный файл.' : 'Автоматические правила отключены. Wordfence и физический robots.txt не изменялись.';
                    $alert_type = 'success';
                }
            }
        } elseif ( 'refresh_crawler_visits' === $action ) {
            waca_traffic_report( true );
            $alert = 'Журнал Wordfence обновлён. Подтверждённые IP отмечены, если доступен официальный список.';
            $alert_type = 'success';
        } elseif ( 'verify_ip' === $action ) {
            $ip = isset( $_POST['waca_ip'] ) ? trim( sanitize_text_field( wp_unslash( $_POST['waca_ip'] ) ) ) : '';
            $feed_id = isset( $_POST['waca_feed'] ) ? sanitize_key( wp_unslash( $_POST['waca_feed'] ) ) : '';
            if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) || ! isset( waca_feeds()[ $feed_id ] ) ) {
                $alert = 'Введите корректный IPv4/IPv6 и выберите источник.';
                $alert_type = 'error';
            } else {
                $feed = waca_get_prefixes( $feed_id );
                if ( is_wp_error( $feed ) ) {
                    $alert = $feed->get_error_message();
                    $alert_type = 'error';
                } else {
                    $matched = '';
                    foreach ( $feed['prefixes'] as $cidr ) {
                        if ( waca_ip_in_cidr( $ip, $cidr ) ) {
                            $matched = $cidr;
                            break;
                        }
                    }
                    $ip_check = array( 'ip' => $ip, 'id' => $feed_id, 'matched' => $matched, 'updated' => $feed['fetched_at'] );
                }
            }
        }
    }

    $scan = get_option( 'waca_last_scan', array() );
    $scan = is_array( $scan ) ? $scan : array();
    $robots_text = isset( $scan['robots_text'] ) ? (string) $scan['robots_text'] : '';
    $active = (array) get_option( 'waca_selected_agents', array() );
    $guard = waca_overlay_possible( $robots_text );
    $wf = waca_active_wordfence();
    $wf_url = admin_url( 'admin.php?page=WordfenceWAF' );
    ?>
    <div class="wrap" style="max-width:1060px">
        <h1>AI Crawler Access for Wordfence</h1>
        <p>Безопасная проверка доступа AI-поисковиков. <strong>Плагин никогда не добавляет IP в исключения Wordfence, не отключает WAF и не доверяет одному User-Agent.</strong></p>
        <?php if ( $alert ) { waca_notice( $alert, $alert_type ); } ?>
        <div style="display:flex;flex-wrap:wrap;gap:12px;margin:16px 0">
            <div class="card" style="flex:1;min-width:220px;margin:0;max-width:none"><h2>Wordfence</h2><p><strong><?php echo $wf ? 'Обнаружен' : 'Не найден / не активен'; ?></strong></p><p><?php echo $wf ? 'WAF остаётся включённым, исключения не создаются.' : 'Диагностика robots.txt доступна и без Wordfence.'; ?></p></div>
            <div class="card" style="flex:1;min-width:220px;margin:0;max-width:none"><h2>robots.txt</h2><p><strong><?php echo waca_has_physical_robots() ? 'Физический файл' : 'Физический файл не найден'; ?></strong></p><p><?php echo waca_has_physical_robots() ? 'Автодобавление в WordPress не изменит физический файл.' : 'Возможно добавление через WordPress, если запросы до него доходят.'; ?></p></div>
            <div class="card" style="flex:1;min-width:220px;margin:0;max-width:none"><h2>Правила AI</h2><p><strong><?php echo esc_html( (string) count( $active ) ); ?> выбрано</strong></p><p>Только robots.txt, не исключения из WAF.</p></div>
        </div>

        <h2>1. Диагностика публичных адресов</h2>
        <p>Проверяем доступность от имени <strong>вашего сервера</strong>, без подмены User-Agent. Успешный ответ не подтверждает, что реальные AI-боты проходят Wordfence, CDN или Nginx.</p>
        <form method="post"><?php wp_nonce_field( 'waca_admin_action', 'waca_nonce' ); ?><input type="hidden" name="waca_action" value="diagnose"><?php submit_button( 'Проверить сайт', 'secondary', 'submit', false ); ?></form>
        <?php if ( $scan ) : ?>
            <p>Последняя проверка: <?php echo esc_html( wp_date( 'd.m.Y H:i:s', (int) $scan['time'] ) ); ?></p>
            <table class="widefat striped" style="max-width:850px"><thead><tr><th>Адрес</th><th>HTTP</th><th>Content-Type / ошибка</th></tr></thead><tbody>
                <?php foreach ( array( 'home' => '/', 'robots' => '/robots.txt', 'llms' => '/llms.txt' ) as $key => $url ) : ?>
                    <?php $entry = isset( $scan[ $key ] ) && is_array( $scan[ $key ] ) ? $scan[ $key ] : array(); ?>
                    <tr><td><a href="<?php echo esc_url( home_url( $url ) ); ?>" target="_blank" rel="noopener noreferrer"><?php echo esc_html( $url ); ?></a></td><td><?php echo esc_html( isset( $entry['code'] ) && $entry['code'] ? (string) $entry['code'] : 'Нет ответа' ); ?></td><td><?php echo esc_html( isset( $entry['detail'] ) ? $entry['detail'] : '—' ); ?></td></tr>
                <?php endforeach; ?>
            </tbody></table>
        <?php endif; ?>

        <?php waca_render_traffic(); ?>

        <h2 style="margin-top:25px">3. Разрешения в robots.txt</h2>
        <p>Поставьте галочки только если вы <strong>хотите разрешить этим роботам обход общедоступных страниц</strong>. Плагин не меняет файл на диске и не трогает существующие специальные группы. Для защиты административных адресов сохраняются запреты <code>/wp-admin/</code> и <code>/wp-login.php</code>.</p>
        <?php if ( $guard ) { waca_notice( $guard ); } ?>
        <form method="post" style="background:#fff;border:1px solid #c3c4c7;padding:16px;max-width:810px">
            <?php wp_nonce_field( 'waca_admin_action', 'waca_nonce' ); ?>
            <input type="hidden" name="waca_action" value="update_rules">
            <?php foreach ( waca_agents() as $token => $details ) : ?>
                <label style="display:block;margin:10px 0"><input type="checkbox" name="waca_agents[]" value="<?php echo esc_attr( $token ); ?>" <?php checked( in_array( $token, $active, true ) ); ?>> <strong><?php echo esc_html( $token ); ?></strong> — <?php echo esc_html( $details['company'] . ': ' . $details['purpose'] ); ?></label>
            <?php endforeach; ?>
            <p class="description">Если есть специальные директивы для одного из этих ботов, они сохраняются — автоматическая группа для него не создаётся. Если общий robots.txt запрещает другие пути, автоматическое разрешение блокируется. Googlebot здесь не переписывается, а Google-Extended — отдельный токен политики использования данных. GPTBot и ClaudeBot (обучение) не разрешаются автоматически.</p>
            <?php submit_button( 'Сохранить правила robots.txt', 'primary', 'submit', false ); ?>
        </form>
        <?php if ( $robots_text ) : ?>
            <h3>Пример итогового robots.txt WordPress</h3>
            <textarea readonly rows="9" style="width:100%;max-width:850px;font-family:monospace;font-size:12px"><?php echo esc_textarea( waca_overlay_text( $robots_text, $active ) ); ?></textarea>
            <p class="description">Предпросмотр основан на последнем HTTP-ответе и может отличаться от фактического вывода WordPress. Проверьте <a href="<?php echo esc_url( home_url( '/robots.txt' ) ); ?>" target="_blank" rel="noopener noreferrer">опубликованный robots.txt</a>.</p>
        <?php endif; ?>

        <h2 style="margin-top:26px">4. Проверка IP-адреса из Wordfence Live Traffic</h2>
        <p>Возьмите IP подозрительного запроса из Wordfence → Tools → Live Traffic и сравните с официальными диапазонами. <strong>Совпадение IP не доказывает подлинность User-Agent</strong>; также необходимо сопоставить его с записью в журнале. IP не сохраняется на сайте.</p>
        <form method="post" style="background:#fff;border:1px solid #c3c4c7;padding:16px;max-width:810px">
            <?php wp_nonce_field( 'waca_admin_action', 'waca_nonce' ); ?>
            <input type="hidden" name="waca_action" value="verify_ip">
            <label for="waca_ip"><strong>IP-адрес</strong></label>
            <input id="waca_ip" type="text" name="waca_ip" placeholder="203.0.113.5" size="28" required autocomplete="off">
            <label for="waca_feed"><strong>Источник</strong></label>
            <select id="waca_feed" name="waca_feed">
                <?php foreach ( waca_feeds() as $id => $feed ) : ?><option value="<?php echo esc_attr( $id ); ?>"><?php echo esc_html( $feed['label'] ); ?></option><?php endforeach; ?>
            </select>
            <?php submit_button( 'Проверить IP', 'secondary', 'submit', false ); ?>
        </form>
        <?php if ( $ip_check ) : ?>
            <?php $name = waca_feeds()[ $ip_check['id'] ]['label']; ?>
            <?php waca_notice( $ip_check['matched'] ? 'IP ' . $ip_check['ip'] . ' входит в опубликованный диапазон ' . $name . ': ' . $ip_check['matched'] . '. Это не разрешение в Wordfence.' : 'IP ' . $ip_check['ip'] . ' не найден в опубликованных диапазонах ' . $name . '. Не добавляйте его в исключения.', $ip_check['matched'] ? 'success' : 'info' ); ?>
            <p class="description">Список получен/закэширован: <?php echo esc_html( wp_date( 'd.m.Y H:i', $ip_check['updated'] ) ); ?>. Источник: <a href="<?php echo esc_url( waca_feeds()[ $ip_check['id'] ]['url'] ); ?>" target="_blank" rel="noopener noreferrer">официальный JSON</a>.</p>
        <?php endif; ?>

        <h2 style="margin-top:26px">5. Если Wordfence блокирует подтверждённого бота</h2>
        <ol style="max-width:850px">
            <li>В <a href="<?php echo esc_url( admin_url( 'admin.php?page=WordfenceTools' ) ); ?>">Wordfence → Tools → Live Traffic</a> отфильтруйте <strong>Blocked by Firewall</strong>. Сверьте IP, User-Agent, URL, время и причину.</li>
            <li>Если срабатывает Rate Limiting, в <a href="<?php echo esc_url( $wf_url ); ?>">Wordfence → Firewall → All Firewall Options</a> проверьте пороги crawler/global requests: безопаснее <strong>Throttle</strong>, а не отключение защиты. Для Google выберите <strong>Verified Google crawlers</strong>, но не «Anyone claiming to be Google».</li>
            <li>При ложном WAF-срабатывании разрешите только конкретный безопасный <strong>URL/параметр</strong> через штатную Wordfence allowlist, а не диапазоны IP и не весь сайт.</li>
            <li>При блокировке Nginx/CDN/Cloudflare Wordfence не поможет: проверьте журналы и правила соответствующего уровня. Если блокировка происходит до загрузки WordPress, этот мини-плагин её не видит.</li>
        </ol>
        <p><strong>Grok / xAI:</strong> пока нет подтверждённых официальных диапазонов для безопасной автоматической идентификации в рамках плагина. Правила по неподтверждённому User-Agent не создаются. <strong>Claude:</strong> Anthropic не публикует стабильный список IP — проверить подлинность только по агенту нельзя.</p>
        <p class="description">Документация: <a target="_blank" rel="noopener noreferrer" href="https://www.wordfence.com/help/firewall/options/">Wordfence Firewall</a> · <a target="_blank" rel="noopener noreferrer" href="https://www.wordfence.com/help/firewall/rate-limiting/">Rate Limiting</a> · <a target="_blank" rel="noopener noreferrer" href="https://developers.openai.com/api/docs/bots">OpenAI crawlers</a> · <a target="_blank" rel="noopener noreferrer" href="https://developers.google.com/crawling/docs/crawlers-fetchers/google-common-crawlers">Google</a> · <a target="_blank" rel="noopener noreferrer" href="https://docs.perplexity.ai/guides/bots">Perplexity</a> · <a target="_blank" rel="noopener noreferrer" href="https://support.anthropic.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler">Anthropic</a></p>
    </div>
    <?php
}

/** WPR Update Hub SDK v2: native WordPress update checks; optional anonymous telemetry. */
require_once __DIR__ . '/includes/wpr-updates-client.php';
WPR_Updates_Client_V2::register(__FILE__, array(
    'slug' => 'ai-crawler-access-for-wordfence',
    'server' => 'https://xn----ctbgf6biedka.xn--p1ai',
    'telemetry' => true,
));
