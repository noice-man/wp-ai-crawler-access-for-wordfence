<?php
/**
 * Read-only Wordfence Live Traffic reporter for AI crawler requests.
 * Does not modify the Wordfence database, WAF, configuration or its UI.
 */
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/** Google-Extended is a robots policy token, not a separate crawler User-Agent. */
function waca_traffic_bots() {
    return array(
        'OAI-SearchBot'     => array( 'label' => 'ChatGPT — поиск', 'feed' => 'openai_search' ),
        'ChatGPT-User'      => array( 'label' => 'ChatGPT — запрос пользователя', 'feed' => 'openai_user' ),
        'GPTBot'            => array( 'label' => 'OpenAI — обучение', 'feed' => 'openai_gptbot' ),
        'Googlebot'         => array( 'label' => 'Google / поиск (не отдельный бот Gemini)', 'feed' => 'googlebot' ),
        'PerplexityBot'     => array( 'label' => 'Perplexity — поиск', 'feed' => 'perplexity' ),
        'Perplexity-User'   => array( 'label' => 'Perplexity — запрос пользователя', 'feed' => 'perplexity_user' ),
        'Claude-SearchBot' => array( 'label' => 'Claude — поиск', 'feed' => 'anthropic' ),
        'Claude-User'      => array( 'label' => 'Claude — запрос пользователя', 'feed' => 'anthropic' ),
        'ClaudeBot'        => array( 'label' => 'Claude — обучение', 'feed' => 'anthropic' ),
        'GrokBot'           => array( 'label' => 'Grok / xAI — заявленный User-Agent', 'feed' => '' ),
    );
}

/** Read-only inspection of the Wordfence logging mode. */
function waca_wordfence_traffic_mode() {
    if ( ! waca_active_wordfence() ) {
        return 'absent';
    }
    if ( ( defined( 'WORDFENCE_DISABLE_LIVE_TRAFFIC' ) && WORDFENCE_DISABLE_LIVE_TRAFFIC ) ||
         ( defined( 'WF_IS_WP_ENGINE' ) && WF_IS_WP_ENGINE ) ) {
        return 'forced';
    }
    if ( ! class_exists( 'wfConfig', false ) || ! method_exists( 'wfConfig', 'get' ) ) {
        return 'unknown';
    }
    $setting = wfConfig::get( 'liveTrafficEnabled', null );
    if ( null === $setting ) {
        return 'unknown';
    }
    return in_array( $setting, array( true, 1, '1' ), true ) ? 'all' : 'security';
}

/** Exact table discovery: Wordfence commonly uses lowercase wfhits. */
function waca_wordfence_hits_table() {
    global $wpdb;
    $prefix = $wpdb->base_prefix;
    foreach ( array( 'wfhits', 'wfHits' ) as $suffix ) {
        $candidate = $prefix . $suffix;
        $found = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $candidate ) ) );
        if ( $candidate === $found ) {
            return $candidate;
        }
    }
    return '';
}

function waca_traffic_classify_ua( $ua ) {
    foreach ( waca_traffic_bots() as $token => $data ) {
        if ( preg_match( '~(?<![A-Za-z0-9_-])' . preg_quote( $token, '~' ) . '(?![A-Za-z0-9_-])~i', (string) $ua ) ) {
            return $token;
        }
    }
    return '';
}

/** Wordfence stores a binary representation of the IP (4 or 16 bytes). */
function waca_traffic_ip( $packed ) {
    if ( ! is_string( $packed ) || ! in_array( strlen( $packed ), array( 4, 16 ), true ) ) {
        return '';
    }
    $ip = @inet_ntop( $packed );
    return is_string( $ip ) ? $ip : '';
}

function waca_traffic_blocked( $code, $action ) {
    if ( preg_match( '/^(blocked|lockedout|throttled|rateblocked)/i', trim( (string) $action ) ) ) {
        return true;
    }
    return in_array( (int) $code, array( 401, 403, 429 ), true );
}

function waca_traffic_successful( $code, $action ) {
    return ! waca_traffic_blocked( $code, $action ) && (int) $code >= 200 && (int) $code < 300;
}

/**
 * An admin can inspect public URL paths, but querystrings/fragments/userinfo are
 * removed to avoid persisting or disclosing tokens from the access log.
 */
function waca_traffic_public_path( $url, $site_host ) {
    $url = (string) $url;
    if ( '' === $url || strlen( $url ) > 8192 ) {
        return '';
    }
    $host = (string) wp_parse_url( $url, PHP_URL_HOST );
    if ( '' !== $host && strtolower( rtrim( $host, '.' ) ) !== strtolower( rtrim( (string) $site_host, '.' ) ) ) {
        return '';
    }
    $path = (string) wp_parse_url( $url, PHP_URL_PATH );
    if ( '' === $path ) {
        return '/';
    }
    if ( '/' !== substr( $path, 0, 1 ) || preg_match( '/[\x00-\x1f\x7f]/', $path ) ) {
        return '';
    }
    return substr( $path, 0, 320 );
}

/** A small bounded sample; not a claim to contain all requests in 7/30 days. */
function waca_traffic_rows() {
    global $wpdb;
    if ( ! waca_active_wordfence() ) {
        return array( 'error' => 'Wordfence не активен.', 'rows' => array() );
    }
    $table = waca_wordfence_hits_table();
    if ( ! $table ) {
        return array( 'error' => 'Таблица Wordfence Live Traffic (wfhits) не найдена.', 'rows' => array() );
    }
    $quoted = '`' . str_replace( '`', '``', $table ) . '`';
    $columns = $wpdb->get_col( 'SHOW COLUMNS FROM ' . $quoted, 0 ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
    $columns = is_array( $columns ) ? $columns : array();
    foreach ( array( 'ctime', 'UA', 'IP' ) as $required ) {
        if ( ! in_array( $required, $columns, true ) ) {
            return array( 'error' => 'Схема Live Traffic не поддерживается: отсутствует ' . $required . '.', 'rows' => array() );
        }
    }
    $fields = array( 'ctime', 'UA', 'IP' );
    foreach ( array( 'statusCode', 'action', 'URL' ) as $optional ) {
        if ( in_array( $optional, $columns, true ) ) {
            $fields[] = $optional;
        }
    }
    $select = implode( ', ', array_map( static function ( $name ) { return '`' . $name . '`'; }, $fields ) );
    $limit = 5000;
    $rows = $wpdb->get_results( 'SELECT ' . $select . ' FROM ' . $quoted . ' ORDER BY `ctime` DESC LIMIT ' . (int) $limit, ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
    if ( ! is_array( $rows ) ) {
        return array( 'error' => 'Не удалось прочитать журнал Wordfence.', 'rows' => array() );
    }
    return array( 'error' => '', 'rows' => $rows, 'limit' => $limit, 'has_status' => in_array( 'statusCode', $fields, true ) );
}

/** Verification status is scoped to the specific operator's official feed. */
function waca_traffic_verify_ip( $ip, $feed_id, $feed_states ) {
    if ( ! $feed_id || ! $ip ) {
        return 'unavailable';
    }
    if ( ! array_key_exists( $feed_id, $feed_states ) || ! is_array( $feed_states[ $feed_id ] ) ) {
        return 'not_checked';
    }
    $feed = $feed_states[ $feed_id ];
    if ( empty( $feed['prefixes'] ) || ! is_array( $feed['prefixes'] ) ) {
        return 'not_checked';
    }
    foreach ( $feed['prefixes'] as $cidr ) {
        if ( waca_ip_in_cidr( $ip, $cidr ) ) {
            return 'matched';
        }
    }
    return 'not_matched';
}

function waca_traffic_count_blank() {
    return array( 'total' => 0, 'ok' => 0, 'blocked' => 0, 'http_errors' => 0, 'verified_ok' => 0 );
}

function waca_traffic_count_add( &$counters, $event ) {
    $counters['total']++;
    if ( waca_traffic_successful( $event['http'], $event['action'] ) ) {
        $counters['ok']++;
        if ( 'matched' === $event['auth'] ) {
            $counters['verified_ok']++;
        }
    }
    if ( waca_traffic_blocked( $event['http'], $event['action'] ) ) {
        $counters['blocked']++;
    }
    if ( $event['http'] >= 400 && $event['http'] < 600 ) {
        $counters['http_errors']++;
    }
}

/**
 * We retain historical latest timestamps from 1.1.0, but don't reuse historical
 * logs for 7/30-day counts. They are per-scan bounded samples, not analytics totals.
 */
function waca_traffic_report( $force = false ) {
    $cache_key = 'waca_recent_crawler_report_v2';
    if ( ! $force ) {
        $cache = get_transient( $cache_key );
        if ( is_array( $cache ) ) {
            return $cache;
        }
    }

    $query = waca_traffic_rows();
    $persistent = get_option( 'waca_crawler_last_seen', array() );
    $persistent = is_array( $persistent ) ? $persistent : array();
    // v1.1.0 stored complete URLs, sometimes including query tokens. Strip them
    // during migration before any old entry can be printed by v1.2.0.
    $home_host = strtolower( (string) wp_parse_url( home_url( '/' ), PHP_URL_HOST ) );
    $legacy_cleaned = false;
    foreach ( $persistent as $saved_bot => $saved_types ) {
        if ( ! is_array( $saved_types ) ) {
            continue;
        }
        foreach ( $saved_types as $saved_kind => $saved_event ) {
            if ( ! is_array( $saved_event ) || ! isset( $saved_event['url'] ) ) {
                continue;
            }
            $clean_url = waca_traffic_public_path( $saved_event['url'], $home_host );
            if ( $clean_url !== $saved_event['url'] ) {
                $persistent[ $saved_bot ][ $saved_kind ]['url'] = $clean_url;
                $legacy_cleaned = true;
            }
        }
    }
    $known = waca_traffic_bots();
    $found = array();
    $counts = array();
    $recent = array();
    $feed_states = array();
    $feed_errors = array();
    $now = time();
    $cutoffs = array( '7' => $now - 7 * DAY_IN_SECONDS, '30' => $now - 30 * DAY_IN_SECONDS );
    $site_host = strtolower( (string) wp_parse_url( home_url( '/' ), PHP_URL_HOST ) );
    $oldest = 0;
    $usable = 0;
    foreach ( $known as $name => $info ) {
        $counts[ $name ] = array( '7' => waca_traffic_count_blank(), '30' => waca_traffic_count_blank() );
        $recent[ $name ] = array();
    }

    foreach ( $query['rows'] as $hit ) {
        if ( ! is_array( $hit ) ) {
            continue;
        }
        $timestamp = isset( $hit['ctime'] ) ? (int) $hit['ctime'] : 0;
        if ( $timestamp <= 0 || $timestamp > $now + 86400 ) {
            continue;
        }
        $oldest = 0 === $oldest ? $timestamp : min( $oldest, $timestamp );
        $url = isset( $hit['URL'] ) ? (string) $hit['URL'] : '';
        $hit_host = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) );
        if ( '' !== $site_host && '' !== $hit_host && rtrim( $hit_host, '.' ) !== rtrim( $site_host, '.' ) ) {
            continue; // Wordfence's DB may span network sites.
        }
        $usable++;
        $name = waca_traffic_classify_ua( isset( $hit['UA'] ) ? $hit['UA'] : '' );
        if ( '' === $name ) {
            continue;
        }
        $feed_id = $known[ $name ]['feed'];
        if ( $feed_id && ! array_key_exists( $feed_id, $feed_states ) ) {
            $state = get_transient( 'waca_feed_' . $feed_id );
            if ( $force && ( ! is_array( $state ) || empty( $state['prefixes'] ) ) ) {
                $state = waca_get_prefixes( $feed_id );
            }
            if ( is_wp_error( $state ) ) {
                $feed_errors[ $feed_id ] = $state->get_error_message();
                $state = false;
            }
            $feed_states[ $feed_id ] = $state;
        }
        $code = isset( $hit['statusCode'] ) ? (int) $hit['statusCode'] : 0;
        $action = isset( $hit['action'] ) ? substr( (string) $hit['action'], 0, 80 ) : '';
        $ip = waca_traffic_ip( isset( $hit['IP'] ) ? $hit['IP'] : '' );
        $event = array(
            'time' => $timestamp,
            'http' => $code,
            'action' => $action,
            'ip' => $ip,
            'url' => waca_traffic_public_path( $url, $site_host ),
            'auth' => waca_traffic_verify_ip( $ip, $feed_id, $feed_states ),
        );
        if ( ! isset( $found[ $name ] ) ) {
            $found[ $name ] = array();
        }
        foreach ( array( 'seen' => true, 'success' => waca_traffic_successful( $code, $action ), 'verified' => 'matched' === $event['auth'], 'verified_success' => 'matched' === $event['auth'] && waca_traffic_successful( $code, $action ), 'blocked' => waca_traffic_blocked( $code, $action ) ) as $kind => $eligible ) {
            if ( $eligible && ( ! isset( $found[ $name ][ $kind ] ) || (int) $found[ $name ][ $kind ]['time'] < $timestamp ) ) {
                $found[ $name ][ $kind ] = $event;
            }
        }
        foreach ( $cutoffs as $days => $cutoff ) {
            if ( $timestamp >= $cutoff ) {
                waca_traffic_count_add( $counts[ $name ][ $days ], $event );
            }
        }
        if ( count( $recent[ $name ] ) < 5 ) {
            $recent[ $name ][] = $event;
        }
    }
    foreach ( $found as $name => $items ) {
        foreach ( $items as $kind => $event ) {
            if ( ! isset( $persistent[ $name ][ $kind ] ) || (int) $persistent[ $name ][ $kind ]['time'] < (int) $event['time'] ||
                 (int) $persistent[ $name ][ $kind ]['time'] === (int) $event['time'] ) {
                // Equal timestamps upgrade legacy entries with auth/action/path details.
                $persistent[ $name ][ $kind ] = $event;
            }
        }
    }
    if ( $found || $legacy_cleaned ) {
        update_option( 'waca_crawler_last_seen', $persistent, false );
    }
    $report = array(
        'error' => isset( $query['error'] ) ? $query['error'] : '',
        'scanned_at' => $now,
        'rows_read' => count( $query['rows'] ),
        'limit' => isset( $query['limit'] ) ? $query['limit'] : 5000,
        'oldest' => $oldest,
        'usable' => $usable,
        'has_status' => isset( $query['has_status'] ) ? $query['has_status'] : false,
        'bots' => $persistent,
        'counts' => $counts,
        'recent' => $recent,
        'feed_errors' => $feed_errors,
        'feeds' => array_map( static function ( $feed ) {
            return is_array( $feed ) && ! empty( $feed['prefixes'] ) ? (int) $feed['fetched_at'] : 0;
        }, $feed_states ),
    );
    set_transient( $cache_key, $report, 5 * MINUTE_IN_SECONDS );
    return $report;
}

function waca_traffic_date( $entry ) {
    return isset( $entry['time'] ) && (int) $entry['time'] > 0 ? wp_date( 'd.m.Y H:i', (int) $entry['time'] ) : '—';
}

function waca_traffic_auth_label( $auth, $feed ) {
    if ( '' === $feed ) {
        return 'Нет официальной проверки';
    }
    if ( 'matched' === $auth ) {
        return 'IP совпадает с официальным диапазоном';
    }
    if ( 'not_matched' === $auth ) {
        return 'IP не совпадает с опубликованным диапазоном';
    }
    return 'Не проверено';
}

function waca_traffic_http_label( $entry ) {
    $code = isset( $entry['http'] ) ? (int) $entry['http'] : 0;
    $action = isset( $entry['action'] ) ? $entry['action'] : '';
    if ( waca_traffic_blocked( $code, $action ) ) {
        return ( $code ? 'HTTP ' . $code . ', ' : '' ) . 'Ограничен';
    }
    return $code ? 'HTTP ' . $code : 'HTTP неизвестен';
}

function waca_traffic_details_url( $path ) {
    if ( ! is_string( $path ) || '' === $path || '/' !== substr( $path, 0, 1 ) || '//' === substr( $path, 0, 2 ) ) {
        return '';
    }
    return home_url( $path );
}

function waca_render_traffic() {
    $mode = waca_wordfence_traffic_mode();
    $settings_url = admin_url( 'admin.php?page=Wordfence&subpage=global_options' );
    $live_url = admin_url( 'admin.php?page=WordfenceTools&subpage=livetraffic' );
    $report = waca_traffic_report();
    $bot_defs = waca_traffic_bots();
    ?>
    <h2 style="margin-top:28px">2. Последние визиты AI-краулеров</h2>
    <p>Данные из <strong>Wordfence Live Traffic</strong> — журнал читается без изменений. Отметки отображаются в нашем плагине, не внутри интерфейса Wordfence. <a href="<?php echo esc_url( $live_url ); ?>">Открыть Live Traffic ↗</a></p>
    <?php if ( 'absent' === $mode ) : ?>
        <?php waca_notice( 'Wordfence не обнаружен. Для этих данных нужен активный Wordfence.' ); ?>
    <?php elseif ( 'all' === $mode ) : ?>
        <?php waca_notice( 'Включён All Traffic. Регистрируются также обычные посещения, доходящие до Wordfence.', 'success' ); ?>
    <?php elseif ( 'forced' === $mode ) : ?>
        <?php waca_notice( 'Live Traffic ограничен конфигурацией Wordfence/хостинга. All Traffic может быть недоступен.' ); ?>
    <?php else : ?>
        <?php waca_notice( 'Чтобы видеть успешные визиты, рекомендуем Wordfence → Live Traffic → Traffic logging mode → All Traffic. Текущий режим: ' . ( 'security' === $mode ? 'Security Only' : 'не удалось определить' ) ); ?>
    <?php endif; ?>
    <?php if ( 'absent' !== $mode ) : ?>
        <p><a class="button button-secondary" href="<?php echo esc_url( $settings_url ); ?>">Настройки Wordfence ↗</a> <a class="button button-secondary" href="<?php echo esc_url( $live_url ); ?>">Журнал ↗</a></p>
        <p class="description" style="max-width:980px">В Wordfence откройте Tools → Live Traffic → Live Traffic Options или All Options → Tool Options → Live Traffic Options. Выберите <strong>All Traffic</strong> и сохраните. На сайтах с высоким трафиком режим увеличивает объём БД и нагрузку. Плагин не включает его автоматически.</p>
    <?php endif; ?>
    <form method="post" style="margin:18px 0">
        <?php wp_nonce_field( 'waca_admin_action', 'waca_nonce' ); ?>
        <input type="hidden" name="waca_action" value="refresh_crawler_visits">
        <?php submit_button( 'Обновить журнал и проверить IP', 'secondary', 'submit', false ); ?>
        <span class="description">При первом запуске загружаются официальные IP-списки; это может занять некоторое время.</span>
    </form>
    <?php if ( $report['error'] ) { waca_notice( $report['error'], 'error' ); } ?>
    <p class="description">Сканирование: <?php echo esc_html( wp_date( 'd.m.Y H:i', (int) $report['scanned_at'] ) ); ?>. Прочитано <?php echo esc_html( (string) $report['rows_read'] ); ?> из последних <?php echo esc_html( (string) $report['limit'] ); ?> записей Wordfence. Старейшая запись выборки: <strong><?php echo esc_html( $report['oldest'] ? wp_date( 'd.m.Y H:i', (int) $report['oldest'] ) : '—' ); ?></strong>.</p>
    <?php if ( $report['rows_read'] >= $report['limit'] ) : ?>
        <?php waca_notice( 'Журнал больше выборки: данные за 7/30 дней могут быть неполными. Показаны только запросы из последних ' . $report['limit'] . ' записей, а не полный трафик за месяц.' ); ?>
    <?php endif; ?>
    <?php if ( 'all' !== $mode ) : ?>
        <?php waca_notice( 'Счётчики не отражают весь трафик, пока не включён All Traffic. Даже после включения Wordfence может удалять старые записи.' ); ?>
    <?php endif; ?>
    <p class="description">Счётчики — число совпавших запросов <strong>в доступной выборке Wordfence</strong> за последние 7 и 30 дней (всего / HTTP 2xx / ограничения 401, 403, 429 или block-действия). Это не оценка полного количества запросов, индексации или охвата. URL показан без параметров запроса, чтобы не раскрывать токены.</p>
    <div style="overflow-x:auto;max-width:100%"><table class="widefat striped" style="min-width:1030px">
        <thead><tr><th>Краулер</th><th>Последнее обращение</th><th>Результат и URL последнего обращения</th><th>Подтверждение IP</th><th>Последний подтверждённый HTTP 2xx</th><th>За 7 дней<br><small>всего / 2xx / ограничения</small></th><th>За 30 дней<br><small>всего / 2xx / ограничения</small></th></tr></thead>
        <tbody>
        <?php foreach ( $bot_defs as $token => $info ) :
            $last = isset( $report['bots'][ $token ] ) && is_array( $report['bots'][ $token ] ) ? $report['bots'][ $token ] : array();
            $seen = isset( $last['seen'] ) && is_array( $last['seen'] ) ? $last['seen'] : array();
            $verified_success = isset( $last['verified_success'] ) && is_array( $last['verified_success'] ) ? $last['verified_success'] : array();
            $count7 = $report['counts'][ $token ]['7'];
            $count30 = $report['counts'][ $token ]['30'];
            $auth = isset( $seen['auth'] ) ? $seen['auth'] : 'not_checked';
            $path = isset( $seen['url'] ) ? $seen['url'] : '';
            $link = waca_traffic_details_url( $path );
            ?>
            <tr>
                <td><strong><?php echo esc_html( $token ); ?></strong><br><span class="description"><?php echo esc_html( $info['label'] ); ?></span></td>
                <td><?php echo esc_html( waca_traffic_date( $seen ) ); ?></td>
                <td><?php echo $seen ? esc_html( waca_traffic_http_label( $seen ) ) : '—'; ?><br>
                    <?php if ( $seen && ! empty( $seen['ip'] ) ) : ?><code><?php echo esc_html( $seen['ip'] ); ?></code><br><?php endif; ?>
                    <?php if ( $link ) : ?><a href="<?php echo esc_url( $link ); ?>" target="_blank" rel="noopener noreferrer"><code><?php echo esc_html( $path ); ?></code> ↗</a><?php elseif ( $path ) : ?><code><?php echo esc_html( $path ); ?></code><?php endif; ?></td>
                <td><?php echo esc_html( $seen ? waca_traffic_auth_label( $auth, $info['feed'] ) : '—' ); ?></td>
                <td><?php echo esc_html( waca_traffic_date( $verified_success ) ); ?></td>
                <td><strong><?php echo esc_html( implode( ' / ', array( $count7['total'], $count7['ok'], $count7['blocked'] ) ) ); ?></strong></td>
                <td><strong><?php echo esc_html( implode( ' / ', array( $count30['total'], $count30['ok'], $count30['blocked'] ) ) ); ?></strong></td>
            </tr>
            <?php if ( ! empty( $report['recent'][ $token ] ) ) : ?>
            <tr><td colspan="7" style="padding:0 12px 12px"><details><summary style="cursor:pointer;padding:8px 0">Последние <?php echo esc_html( (string) count( $report['recent'][ $token ] ) ); ?> запросов <?php echo esc_html( $token ); ?></summary>
                <table class="widefat" style="margin-top:8px"><thead><tr><th>Время</th><th>HTTP / событие</th><th>IP</th><th>URL (без query)</th><th>Проверка IP</th></tr></thead><tbody>
                <?php foreach ( $report['recent'][ $token ] as $request ) :
                    $req_url = waca_traffic_details_url( $request['url'] ); ?>
                    <tr><td><?php echo esc_html( waca_traffic_date( $request ) ); ?></td>
                        <td><?php echo esc_html( waca_traffic_http_label( $request ) ); ?></td>
                        <td><code><?php echo esc_html( $request['ip'] ?: '—' ); ?></code></td>
                        <td><?php if ( $req_url ) : ?><a href="<?php echo esc_url( $req_url ); ?>" target="_blank" rel="noopener noreferrer"><?php echo esc_html( $request['url'] ); ?></a><?php else : ?><?php echo esc_html( $request['url'] ?: '—' ); ?><?php endif; ?></td>
                        <td><?php echo esc_html( waca_traffic_auth_label( $request['auth'], $info['feed'] ) ); ?></td></tr>
                <?php endforeach; ?>
                </tbody></table></details></td></tr>
            <?php endif; ?>
        <?php endforeach; ?>
        </tbody>
    </table></div>
    <?php if ( ! empty( $report['feed_errors'] ) ) : ?>
        <p><strong>Ошибки IP-проверки:</strong></p><ul>
            <?php foreach ( $report['feed_errors'] as $feed_id => $message ) : ?>
                <li><?php echo esc_html( $feed_id . ': ' . $message ); ?></li>
            <?php endforeach; ?>
        </ul>
    <?php endif; ?>
    <p class="description" style="max-width:1100px">Подлинность определяется сравнением IP Wordfence с <strong>текущими</strong> официальными списками IP оператора, а не по одному User-Agent. Для Anthropic проверка теперь доступна по опубликованному списку Claude. Если IP не совпал, возможны подмена UA, изменение диапазонов, прокси или конфигурация Wordfence. Даже подтверждённое совпадение не доказывает, что запрос был инициирован конкретным продуктом; например, Googlebot не тождественен Gemini. Отдельные проверки для Grok отсутствуют. Успешный 2xx не гарантирует индексацию и чтение всей страницы. Запросы, остановленные Nginx/CDN или ранним WAF, могут не попасть в журнал.</p>
    <?php
}
